import { Inject, Injectable, NotFoundException, BadRequestException, UnauthorizedException, Optional } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { Profile } from 'passport-google-oauth20';
import crypto from 'node:crypto';

import { AUTH_MAILER, AUTH_MODULE_OPTIONS, AUTH_RESET_TOKEN_STORE, AUTH_USERS_SERVICE } from './internal/tokens';
import type { AuthModuleOptions } from './interfaces/options.interface';
import type { AuthUsersService } from './interfaces/auth-users-service.interface';
import type { PasswordResetTokenStore } from './interfaces/password-reset-token-store.interface';
import type { AuthMailer } from './interfaces/mailer.interface';
import type { AuthUser } from './interfaces/auth-user.interface';
import { RegisterDto } from './dto/register.dto';

@Injectable()
export class AuthService {
  constructor(
    @Inject(AUTH_USERS_SERVICE) private readonly users: AuthUsersService,
    private readonly jwt: JwtService,
    @Inject(AUTH_RESET_TOKEN_STORE)
    private readonly resetStore: PasswordResetTokenStore,
    @Optional()
    @Inject(AUTH_MAILER)
    private readonly mailer: AuthMailer | null,
    @Inject(AUTH_MODULE_OPTIONS)
    private readonly opts: AuthModuleOptions
  ) {}

  private hashToken(token: string) {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  async validateUser(identifier: string, password: string): Promise<AuthUser> {
    const user = await this.users.validateCredentials(identifier, password);
    if (!user) throw new UnauthorizedException('Invalid credentials');
    return user;
  }

  async issueAccessToken(user: { id: number; username: string; role?: string | null }) {
    return this.jwt.signAsync({
      sub: user.id,
      username: user.username,
      role: user.role ?? null
    });
  }

  async register(dto: RegisterDto) {
    const user = await this.users.registerUser(dto.username, dto.password, dto.email);
    const accessToken = await this.issueAccessToken({ id: user.id, username: user.username, role: user.role });
    return { user, accessToken };
  }

  async loginWithCredentials(identifier: string, password: string) {
    const user = await this.validateUser(identifier, password);
    const accessToken = await this.issueAccessToken({ id: user.id, username: user.username, role: user.role });
    return { user, accessToken };
  }

  async loginWithGoogleProfile(profile: Profile) {
    const email = profile.emails?.[0]?.value;
    const displayName = profile.displayName || profile.name?.givenName || 'user';
    if (!email) throw new UnauthorizedException('Google account has no email');

    const existed = await this.users.findByEmail(email);
    let user: AuthUser;
    if (existed) {
      user = existed;
    } else {
      const base = (displayName || email.split('@')[0]).replace(/\s+/g, '').slice(0, 20) || 'user';
      user = await this.users.createOAuthUser(email, base);
    }

    const accessToken = await this.issueAccessToken({
      id: user.id,
      username: user.username,
      role: user.role
    });
    return { user, accessToken };
  }

  async createPasswordResetToken(email: string) {
    const user = await this.users.findByEmail(email);
    if (!user) return { ok: true };

    const token = crypto.randomBytes(32).toString('base64url');
    const tokenHash = this.hashToken(token);
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
    await this.resetStore.saveToken(user.id, tokenHash, expiresAt);

    const resetBase = this.opts.frontend?.resetUrlBase ?? '';
    const link = resetBase ? `${resetBase}${token}` : token;

    if (this.mailer && this.mailer.isEnabled() && user.email) {
      const subject = 'Password Reset';
      const html = `<p>You requested a password reset.</p><p>Click the link to reset: <a href=\"${link}\">${link}</a></p><p>If you did not request this, you can ignore this email.</p>`;
      try {
        await this.mailer.send(user.email, subject, html, `Reset link: ${link}`);
      } catch {
        // swallow mailer errors to avoid leaking user existence
      }
    }

    return { ok: true };
  }

  async resetPassword(token: string, newPassword: string) {
    const tokenHash = this.hashToken(token);
    const record = await this.resetStore.findByHash(tokenHash);
    if (!record) throw new NotFoundException('Invalid token');
    if (record.usedAt) throw new BadRequestException('Token already used');
    if (record.expiresAt.getTime() < Date.now()) throw new BadRequestException('Token expired');

    await this.users.updatePassword(record.userId, newPassword);
    await this.resetStore.markUsed(record.id, new Date());

    return { ok: true };
  }
}
