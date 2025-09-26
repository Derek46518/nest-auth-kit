import { JwtService } from '@nestjs/jwt';
import type { Profile } from 'passport-google-oauth20';
import type { AuthModuleOptions } from './interfaces/options.interface';
import type { AuthUsersService } from './interfaces/auth-users-service.interface';
import type { PasswordResetTokenStore } from './interfaces/password-reset-token-store.interface';
import type { AuthMailer } from './interfaces/mailer.interface';
import type { AuthUser } from './interfaces/auth-user.interface';
import { RegisterDto } from './dto/register.dto';
export declare class AuthService {
    private readonly users;
    private readonly jwt;
    private readonly resetStore;
    private readonly mailer;
    private readonly opts;
    constructor(users: AuthUsersService, jwt: JwtService, resetStore: PasswordResetTokenStore, mailer: AuthMailer | null, opts: AuthModuleOptions);
    private hashToken;
    validateUser(identifier: string, password: string): Promise<AuthUser>;
    issueAccessToken(user: {
        id: number;
        username: string;
        role?: string | null;
    }): Promise<string>;
    register(dto: RegisterDto): Promise<{
        user: AuthUser;
        accessToken: string;
    }>;
    loginWithCredentials(identifier: string, password: string): Promise<{
        user: AuthUser;
        accessToken: string;
    }>;
    loginWithGoogleProfile(profile: Profile): Promise<{
        user: AuthUser;
        accessToken: string;
    }>;
    createPasswordResetToken(email: string): Promise<{
        ok: boolean;
    }>;
    resetPassword(token: string, newPassword: string): Promise<{
        ok: boolean;
    }>;
}
