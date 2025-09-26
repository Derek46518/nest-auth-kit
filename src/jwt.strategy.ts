import { Inject, Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import type { Request } from 'express';

import { AUTH_MODULE_OPTIONS } from './internal/tokens';
import type { AuthModuleOptions } from './interfaces/options.interface';

function cookieExtractorFactory(cookieName: string) {
  return (req: Request): string | null => req.cookies?.[cookieName] ?? null;
}

interface JwtPayload {
  sub: number;
  username: string;
  role?: string | null;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(@Inject(AUTH_MODULE_OPTIONS) private readonly opts: AuthModuleOptions) {
    const cookieName = opts.cookies?.cookieName ?? 'accessToken';
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        cookieExtractorFactory(cookieName),
        ExtractJwt.fromAuthHeaderAsBearerToken()
      ]),
      ignoreExpiration: false,
      secretOrKey: opts.jwt.secret
    });
  }

  async validate(payload: JwtPayload) {
    return {
      userId: payload.sub,
      username: payload.username,
      role: payload.role ?? null
    };
  }
}
