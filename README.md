# nest-auth-kit

Reusable NestJS authentication module that bundles:

- Local username/email + password login
- JWT issuance with HttpOnly cookie support
- Google OAuth 2.0 strategy (passport-google-oauth20)
- CSRF double-submit middleware
- Password reset flow with pluggable token persistence
- Optional transactional email notifications

This package extracts the auth stack used in the WebBackend project and exposes
extensible interfaces so you can bring your own user store, reset-token
repository, and mailer implementation.

> **Status**: experimental & work-in-progress. The API may change before 1.0.

## Features

- Dynamic `AuthModule` with configurable providers and cookie behaviour
- Injectable `AuthService` exposing high-level login/registration helpers
- Passport strategies (`local`, `jwt`, `google`) and guards ready to plug into controllers
- CSRF middleware that validates origin + double-submit token
- DTOs for register/forgot/reset flows using `class-validator`

## Installation

```bash
npm install nest-auth-kit passport passport-local passport-jwt passport-google-oauth20
```

The package declares peer dependencies on the relevant NestJS packages. Ensure
your host application already depends on them.

## Quick start

```ts
import { Module } from '@nestjs/common';
import { AuthModule, AuthModuleOptions } from 'nest-auth-kit';
import { CustomUsersService } from './users/users.service';
import { ResetTokenStore } from './auth/reset-token.store';
import { MailerService } from './mailer/mailer.service';

const authOptions: AuthModuleOptions = {
  userService: { provide: 'AUTH_USERS_SERVICE', useExisting: CustomUsersService },
  resetTokenStore: { provide: 'AUTH_RESET_TOKEN_STORE', useExisting: ResetTokenStore },
  mailer: { provide: 'AUTH_MAILER', useExisting: MailerService },
  jwt: {
    secret: process.env.JWT_SECRET!,
    expiresIn: process.env.JWT_EXPIRES_IN ?? '15m',
    cookieName: 'accessToken'
  },
  cookies: {
    useCookies: true,
    cookieDomain: process.env.COOKIE_DOMAIN,
    crossSite: process.env.COOKIE_CROSS_SITE === 'true'
  },
  google: {
    clientID: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    callbackURL: process.env.GOOGLE_CALLBACK_URL!
  }
};

@Module({
  imports: [
    AuthModule.register(authOptions)
  ]
})
export class AppModule {}
```

Register the supplied guards and middleware in your controllers just like in the
original project:

```ts
import { Controller, Post, UseGuards } from '@nestjs/common';
import { LocalAuthGuard, AuthService } from 'nest-auth-kit';

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @Post('login')
  login() {
    // req.user populated by the guard, identical to the original implementation
  }
}
```

## Adapters

`nest-auth-kit` does not ship with database access or user persistence. Instead,
you provide adapters implementing these interfaces:

- `AuthUsersService` – look up and mutate user accounts
- `PasswordResetTokenStore` – persist hashed reset tokens
- `AuthMailer` (optional) – send transactional emails

Example adapters for Drizzle ORM and Nodemailer live in the WebBackend repo under
`src/auth/adapters` and can serve as a reference.

## License

MIT © Derek
