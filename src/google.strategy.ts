import { Inject, Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Profile, Strategy, VerifyCallback } from 'passport-google-oauth20';

import { AuthService } from './auth.service';
import { AUTH_MODULE_OPTIONS } from './internal/tokens';
import type { AuthModuleOptions } from './interfaces/options.interface';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(@Inject(AUTH_MODULE_OPTIONS) opts: AuthModuleOptions, private readonly auth: AuthService) {
    const google = opts.google ?? {
      clientID: 'missing',
      clientSecret: 'missing',
      callbackURL: 'http://localhost:3000/auth/google/callback'
    };

    super({
      clientID: google.clientID || 'missing',
      clientSecret: google.clientSecret || 'missing',
      callbackURL: google.callbackURL || 'http://localhost:3000/auth/google/callback',
      scope: google.scope ?? ['profile', 'email']
    });
  }

  async validate(_accessToken: string, _refreshToken: string, profile: Profile, done: VerifyCallback) {
    try {
      const result = await this.auth.loginWithGoogleProfile(profile);
      return done(null, result.user);
    } catch (err) {
      return done(err as Error);
    }
  }
}
