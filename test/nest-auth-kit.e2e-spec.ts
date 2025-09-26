import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, Module } from '@nestjs/common';
import request from 'supertest';
import crypto from 'node:crypto';

import {
    AuthModule as AuthKitModule,
    AuthModuleOptions,
    AuthUsersService,
    PasswordResetTokenStore,
    PasswordResetTokenRecord,
    AuthMailer,
    AUTH_USERS_SERVICE,
    AUTH_RESET_TOKEN_STORE,
    AUTH_MAILER
} from 'nest-auth-kit';

class FakeUsersServiceAdapter implements AuthUsersService {
    private users = new Map<number, { id: number; username: string; email: string; role: string; password: string }>();
    private nextId = 1;

    private toAuthUser(user: { id: number; username: string; email: string; role: string }) {
        return {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role
        };
    }

    private findByIdentifier(identifier: string) {
        const normalized = identifier.trim().toLowerCase();
        for (const user of this.users.values()) {
            if (user.username.toLowerCase() === normalized || user.email.toLowerCase() === normalized)
                return user;
        }
        return null;
    }

    async validateCredentials(identifier: string, password: string) {
        const user = this.findByIdentifier(identifier);
        if (!user || user.password !== password) return null;
        return this.toAuthUser(user);
    }

    async registerUser(username: string, password: string, email: string) {
        const id = this.nextId++;
        const user = { id, username, email, role: 'user', password };
        this.users.set(id, user);
        return this.toAuthUser(user);
    }

    async findByEmail(email: string) {
        const user = this.findByIdentifier(email);
        return user ? this.toAuthUser(user) : null;
    }

    async createOAuthUser(email: string, usernameBase: string) {
        const existing = await this.findByEmail(email);
        if (existing) return existing;
        let username = usernameBase;
        let suffix = 1;
        while (Array.from(this.users.values()).some((u) => u.username === username)) {
            username = `${usernameBase}${suffix++}`;
        }
        return this.registerUser(username, crypto.randomUUID(), email);
    }

    async updatePassword(userId: number, newPassword: string) {
        const user = this.users.get(userId);
        if (!user) return;
        user.password = newPassword;
    }
}

class FakePasswordResetTokenStoreAdapter implements PasswordResetTokenStore {
    records: PasswordResetTokenRecord[] = [];
    private nextId = 1;

    async saveToken(userId: number, tokenHash: string, expiresAt: Date) {
        this.records.push({ id: this.nextId++, userId, tokenHash, expiresAt, usedAt: null });
    }

    async findByHash(tokenHash: string) {
        const record = this.records.find((r) => r.tokenHash === tokenHash);
        return record ? { ...record } : null;
    }

    async markUsed(id: number, usedAt: Date) {
        const record = this.records.find((r) => r.id === id);
        if (record) record.usedAt = usedAt;
    }
}

class FakeMailer implements AuthMailer {
    sent: Array<{ to: string; subject: string; html: string; text?: string }> = [];

    isEnabled() {
        return true;
    }

    async send(to: string, subject: string, html: string, text?: string) {
        this.sent.push({ to, subject, html, text });
    }
}

@Module({
    providers: [
        FakeUsersServiceAdapter,
        FakePasswordResetTokenStoreAdapter,
        FakeMailer,
        { provide: AUTH_USERS_SERVICE, useExisting: FakeUsersServiceAdapter },
        { provide: AUTH_RESET_TOKEN_STORE, useExisting: FakePasswordResetTokenStoreAdapter },
        { provide: AUTH_MAILER, useExisting: FakeMailer }
    ],
    exports: [
        FakeUsersServiceAdapter,
        FakePasswordResetTokenStoreAdapter,
        FakeMailer,
        AUTH_USERS_SERVICE,
        AUTH_RESET_TOKEN_STORE,
        AUTH_MAILER
    ]
})
class FakeAdaptersModule {}

describe('nest-auth-kit e2e', () => {
    let app: INestApplication;
    let usersAdapter: FakeUsersServiceAdapter;
    let resetStore: FakePasswordResetTokenStoreAdapter;

    beforeAll(async () => {
        const options: AuthModuleOptions = {
            imports: [FakeAdaptersModule],
            userServiceToken: FakeUsersServiceAdapter,
            resetTokenStoreToken: FakePasswordResetTokenStoreAdapter,
            mailerToken: FakeMailer,
            jwt: {
                secret: 'test-secret-1234567890',
                expiresIn: '15m'
            },
            cookies: {
                useCookies: false
            },
            google: undefined,
            frontend: {
                origins: [],
                defaultRedirectUrl: 'http://localhost:3000',
                resetUrlBase: 'http://localhost:3000/reset?token='
            }
        };

        const moduleFixture: TestingModule = await Test.createTestingModule({
            imports: [FakeAdaptersModule, AuthKitModule.register(options)]
        }).compile();

        app = moduleFixture.createNestApplication();
        await app.init();

        usersAdapter = app.get(FakeUsersServiceAdapter);
        resetStore = app.get(FakePasswordResetTokenStoreAdapter);
    });

    afterAll(async () => {
        await app.close();
    });

    it('registers a new user and returns access token', async () => {
        const res = await request(app.getHttpServer())
            .post('/auth/register')
            .send({ username: 'alice', password: 'StrongPass123', email: 'alice@example.com' })
            .expect(201);

        expect(res.body.user).toMatchObject({ username: 'alice', email: 'alice@example.com' });
        expect(typeof res.body.accessToken).toBe('string');
    });

    it('logs in with local credentials', async () => {
        const res = await request(app.getHttpServer())
            .post('/auth/login')
            .send({ username: 'alice', password: 'StrongPass123' })
            .expect(200);

        expect(res.body.user).toMatchObject({ username: 'alice' });
        expect(typeof res.body.accessToken).toBe('string');
    });

    it('issues csrf token', async () => {
        const res = await request(app.getHttpServer()).get('/auth/csrf').expect(200);
        expect(typeof res.body.csrfToken).toBe('string');
    });

    it('persists password reset token and allows reset', async () => {
        await request(app.getHttpServer())
            .post('/auth/password/forgot')
            .send({ email: 'alice@example.com' })
            .expect(200);

        expect(resetStore.records.length).toBeGreaterThan(0);

        // prepare a known token so we can complete reset flow
        const rawToken = 'manual-reset-token';
        const hash = crypto.createHash('sha256').update(rawToken).digest('hex');
        await resetStore.saveToken(1, hash, new Date(Date.now() + 60 * 60 * 1000));

        await request(app.getHttpServer())
            .post('/auth/password/reset')
            .send({ token: rawToken, password: 'AnotherPass456' })
            .expect(200);

        const user = await usersAdapter.validateCredentials('alice', 'AnotherPass456');
        expect(user).not.toBeNull();
    });
});
