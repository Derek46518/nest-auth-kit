import { Injectable, ExecutionContext } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}

@Injectable()
export class GoogleAuthGuard extends AuthGuard('google') {}

@Injectable()
export class GoogleAuthWithStateGuard extends AuthGuard('google') {
  getAuthenticateOptions(context: ExecutionContext) {
    const req = context.switchToHttp().getRequest();
    const redirect = typeof req.query?.redirect === 'string' ? (req.query.redirect as string) : undefined;
    let state: string | undefined;
    if (redirect) {
      try {
        state = Buffer.from(JSON.stringify({ redirect }), 'utf8').toString('base64url');
      } catch {
        // ignore encoding errors
      }
    }
    return state ? { state } : {};
  }
}
