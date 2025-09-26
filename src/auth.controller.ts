import {
  Body,
  Controller,
  Post,
  Res,
  UseGuards,
  Req,
  Get,
  HttpCode,
  Header,
  Inject
} from '@nestjs/common';
import type { Response, Request } from 'express';
import crypto from 'node:crypto';

import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { JwtAuthGuard, LocalAuthGuard, GoogleAuthGuard, GoogleAuthWithStateGuard } from './guards';
import { AUTH_MODULE_OPTIONS } from './internal/tokens';
import type { AuthModuleOptions } from './interfaces/options.interface';

@Controller('auth')
export class AuthController {
  private readonly useCookie: boolean;
  private readonly cookieName: string;
  private readonly csrfCookie: string;
  private readonly csrfHeader: string;
  private readonly cookieDomain?: string;
  private readonly isCrossSite: boolean;
  private readonly secureCookies: boolean;
  private readonly maxAge: number;

  constructor(private readonly auth: AuthService, @Inject(AUTH_MODULE_OPTIONS) private readonly opts: AuthModuleOptions) {
    const cookies = opts.cookies ?? {};
    this.useCookie = cookies.useCookies ?? true;
    this.cookieName = cookies.cookieName ?? 'accessToken';
    this.csrfCookie = cookies.csrfCookieName ?? 'csrfToken';
    this.csrfHeader = cookies.csrfHeaderName ?? 'x-csrf-token';
    this.cookieDomain = cookies.cookieDomain;
    const crossSite = cookies.crossSite ?? false;
    this.isCrossSite = crossSite;
    this.secureCookies = cookies.secureCookies ?? crossSite;
    this.maxAge = cookies.maxAgeMs ?? 60 * 60 * 1000;
  }

  private accessTokenCookieOptions() {
    return {
      httpOnly: true,
      secure: this.secureCookies,
      sameSite: this.isCrossSite ? ('none' as const) : ('lax' as const),
      maxAge: this.maxAge,
      path: '/',
      domain: this.cookieDomain
    };
  }

  private csrfCookieOptions() {
    return {
      httpOnly: false,
      secure: this.secureCookies,
      sameSite: this.isCrossSite ? ('none' as const) : ('lax' as const),
      maxAge: this.maxAge,
      path: '/',
      domain: this.cookieDomain
    };
  }

  private setAuthCookies(res: Response, accessToken: string) {
    res.cookie(this.cookieName, accessToken, this.accessTokenCookieOptions());
    const csrfToken = crypto.randomBytes(32).toString('base64url');
    res.cookie(this.csrfCookie, csrfToken, this.csrfCookieOptions());
    return csrfToken;
  }

  private clearAuthCookies(res: Response) {
    const opts = {
      path: '/',
      domain: this.cookieDomain,
      sameSite: this.isCrossSite ? 'none' : 'lax',
      secure: this.secureCookies
    } as const;
    res.clearCookie(this.cookieName, opts);
    res.clearCookie(this.csrfCookie, opts);
  }

  private buildRedirectUrl(state: string | undefined) {
    const fallback = this.opts.frontend?.defaultRedirectUrl ?? 'http://localhost:3000';
    const origins = this.opts.frontend?.origins ?? [];
    const allowed = origins.length ? origins : [fallback];

    if (!state) return fallback;
    try {
      const parsed = JSON.parse(Buffer.from(state, 'base64url').toString('utf8')) as { redirect?: string };
      const url = parsed?.redirect;
      if (!url) return fallback;
      const target = new URL(url);
      const isAllowed = allowed.some((origin) => {
        try {
          const ref = new URL(origin);
          return ref.protocol === target.protocol && ref.host === target.host;
        } catch {
          return false;
        }
      });
      return isAllowed ? url : fallback;
    } catch {
      return fallback;
    }
  }

  @UseGuards(LocalAuthGuard)
  @Post('login')
  @HttpCode(200)
  @Header('Cache-Control', 'no-store')
  async login(@Res({ passthrough: true }) res: Response, @Req() req: Request) {
    const user = req.user as { id: number; username: string; role?: string | null };
    const accessToken = await this.auth.issueAccessToken({ id: user.id, username: user.username, role: user.role ?? null });
    const csrfToken = this.useCookie ? this.setAuthCookies(res, accessToken) : null;
    if (!this.useCookie) {
      res.setHeader(this.csrfHeader, csrfToken ?? '');
    }
    return { user, accessToken, csrfToken };
  }

  @Post('register')
  @HttpCode(201)
  @Header('Cache-Control', 'no-store')
  async register(@Body() dto: RegisterDto, @Res({ passthrough: true }) res: Response) {
    const { user, accessToken } = await this.auth.register(dto);
    const csrfToken = this.useCookie ? this.setAuthCookies(res, accessToken) : null;
    if (!this.useCookie) {
      res.setHeader(this.csrfHeader, csrfToken ?? '');
    }
    return { user, accessToken, csrfToken };
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  @Header('Cache-Control', 'no-store')
  me(@Req() req: Request) {
    return req.user;
  }

  @Post('logout')
  @HttpCode(200)
  async logout(@Res({ passthrough: true }) res: Response) {
    this.clearAuthCookies(res);
    return { ok: true };
  }

  @Get('csrf')
  @HttpCode(200)
  @Header('Cache-Control', 'no-store')
  getCsrf(@Res({ passthrough: true }) res: Response) {
    const token = crypto.randomBytes(32).toString('base64url');
    res.cookie(this.csrfCookie, token, this.csrfCookieOptions());
    return { csrfToken: token };
  }

  @UseGuards(GoogleAuthWithStateGuard)
  @Get('google')
  googleAuth() {
    // handled by passport
  }

  @UseGuards(GoogleAuthGuard)
  @Get('google/callback')
  @Header('Cache-Control', 'no-store')
  async googleCallback(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const user = req.user as { id: number; username: string; role?: string | null };
    const accessToken = await this.auth.issueAccessToken({ id: user.id, username: user.username, role: user.role ?? null });
    const csrfToken = this.useCookie ? this.setAuthCookies(res, accessToken) : null;

    const state = typeof req.query?.state === 'string' ? (req.query.state as string) : undefined;
    let redirectUrl = this.buildRedirectUrl(state);

    if (!this.useCookie) {
      try {
        const url = new URL(redirectUrl);
        url.searchParams.set('accessToken', accessToken);
        if (csrfToken) url.searchParams.set('csrfToken', String(csrfToken));
        redirectUrl = url.toString();
      } catch {
        return { user, accessToken, csrfToken };
      }
    }

    res.redirect(302, redirectUrl);
    return undefined as any;
  }

  @Post('password/forgot')
  @HttpCode(200)
  async forgotPassword(@Body() dto: ForgotPasswordDto) {
    await this.auth.createPasswordResetToken(dto.email);
    return { ok: true };
  }

  @Post('password/reset')
  @HttpCode(200)
  async resetPassword(@Body() dto: ResetPasswordDto) {
    await this.auth.resetPassword(dto.token, dto.password);
    return { ok: true };
  }
}
