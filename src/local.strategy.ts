import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';

import { AuthService } from './auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly auth: AuthService) {
    super({
      usernameField: 'username',
      passwordField: 'password',
      passReqToCallback: true,
      session: false
    });
  }

  async validate(req: any, username: string, password: string) {
    const body = (req && req.body) || {};
    const identifier = body.identifier ?? body.email ?? body.username ?? username;
    return this.auth.validateUser(String(identifier ?? ''), password);
  }
}
