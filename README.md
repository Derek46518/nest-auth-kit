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

The package declares peer dependencies on core NestJS packages (e.g.
`@nestjs/common`, `@nestjs/jwt`, `@nestjs/passport`). Make sure they already
exist in your host application.

## Usage overview

1. **Implement adapters** that satisfy the exported interfaces.
2. **Provide those adapters** (and optionally a mailer) in a module the kit can
   import.
3. **Register the auth kit** using `AuthModule.registerAsync(...)` (or
   `register(...)`) and supply configuration (JWT, cookies, Google OAuth,
   frontend metadata).
4. **Expose auth endpoints** using the supplied guards/controller or by building
   your own controllers that delegate to `AuthService`.

The following sections walk through each step.

## 1. Implement adapters

Implement the interfaces exported by the kit (see `src/interfaces`):

- `AuthUsersService` – look up users, validate credentials, create accounts, and
  update passwords. Must return objects `{ id, username, email | null, role }`.
- `PasswordResetTokenStore` – persist password reset tokens (`saveToken`,
  `findByHash`, `markUsed`).
- `AuthMailer` *(optional)* – send transactional email. Provide
  `isEnabled(): boolean` to indicate SMTP availability.

Example Drizzle/Nest adapter:

```ts
@Injectable()
export class UsersAuthServiceAdapter implements AuthUsersService {
  constructor(private readonly users: UsersService) {}

  private toAuthUser(user: UsersServiceSafeUser): AuthUser {
    return {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role
    };
  }

  async validateCredentials(identifier: string, password: string) {
    const user = await this.users.validatePassword(identifier, password);
    return user ? this.toAuthUser(user) : null;
  }

  async registerUser(username: string, password: string, email: string) {
    return this.toAuthUser(await this.users.create(username, password, email));
  }

  async findByEmail(email: string) {
    const user = await this.users.findByEmail(email);
    return user ? this.toAuthUser(user as any) : null;
  }

  async createOAuthUser(email: string, usernameBase: string) {
    return this.toAuthUser(await this.users.createOAuthUser(email, usernameBase));
  }

  async updatePassword(userId: number, newPassword: string) {
    await this.users.updatePassword(userId, newPassword);
  }
}
```

Password reset token store example:

```ts
@Injectable()
export class PasswordResetTokenStoreAdapter implements PasswordResetTokenStore {
  constructor(@Inject(DRIZZLE) private readonly db: NodePgDatabase) {}

  async saveToken(userId: number, tokenHash: string, expiresAt: Date) {
    await this.db.insert(passwordResetTokens).values({ userId, tokenHash, expiresAt });
  }

  async findByHash(tokenHash: string) {
    const [row] = await this.db
      .select({
        id: passwordResetTokens.id,
        userId: passwordResetTokens.userId,
        tokenHash: passwordResetTokens.tokenHash,
        expiresAt: passwordResetTokens.expiresAt,
        usedAt: passwordResetTokens.usedAt
      })
      .from(passwordResetTokens)
      .where(eq(passwordResetTokens.tokenHash, tokenHash))
      .limit(1);

    if (!row) return null;
    return {
      id: row.id,
      userId: row.userId,
      tokenHash: row.tokenHash,
      expiresAt: row.expiresAt instanceof Date ? row.expiresAt : new Date(row.expiresAt),
      usedAt: row.usedAt ?? null
    };
  }

  async markUsed(id: number, usedAt: Date) {
    await this.db.update(passwordResetTokens).set({ usedAt }).where(eq(passwordResetTokens.id, id));
  }
}
```

If you want transactional email support, implement `AuthMailer` (or reuse an
existing service) exposing:

```ts
isEnabled(): boolean;
send(to: string, subject: string, html: string, text?: string): Promise<void | boolean>;
```

## 2. Provide adapters & mailer in modules

Create modules that bind your adapters/mailer to the tokens exported by the kit:

```ts
@Module({
  imports: [UsersModule],
  providers: [
    UsersAuthServiceAdapter,
    PasswordResetTokenStoreAdapter,
    { provide: AUTH_USERS_SERVICE, useExisting: UsersAuthServiceAdapter },
    { provide: AUTH_RESET_TOKEN_STORE, useExisting: PasswordResetTokenStoreAdapter }
  ],
  exports: [UsersAuthServiceAdapter, PasswordResetTokenStoreAdapter, AUTH_USERS_SERVICE, AUTH_RESET_TOKEN_STORE]
})
export class AuthAdaptersModule {}

@Module({
  providers: [MailService, { provide: AUTH_MAILER, useExisting: MailService }],
  exports: [MailService, AUTH_MAILER]
})
export class AuthMailerModule {}
```

## 3. Register the auth kit

In your root auth module, configure and import the kit:

```ts
const authKitModule = AuthKitModule.registerAsync({
  imports: [AuthAdaptersModule, AuthMailerModule, ConfigModule],
  useFactory: (cfg: ConfigService): AuthModuleOptions => ({
    imports: [AuthAdaptersModule, AuthMailerModule, ConfigModule],
    userServiceToken: UsersAuthServiceAdapter,
    resetTokenStoreToken: PasswordResetTokenStoreAdapter,
    mailerToken: MailService,
    jwt: {
      secret: cfg.get<string>('JWT_SECRET')!,
      expiresIn: cfg.get<string>('JWT_EXPIRES_IN') ?? '15m'
    },
    cookies: {
      useCookies: cfg.get<string>('AUTH_USE_COOKIE') !== 'false',
      cookieDomain: cfg.get<string>('COOKIE_DOMAIN') || undefined,
      crossSite: cfg.get<string>('COOKIE_CROSS_SITE') === 'true'
    },
    google: cfg.get<string>('GOOGLE_CLIENT_ID') && cfg.get<string>('GOOGLE_CLIENT_SECRET')
      ? {
          clientID: cfg.get<string>('GOOGLE_CLIENT_ID')!,
          clientSecret: cfg.get<string>('GOOGLE_CLIENT_SECRET')!,
          callbackURL: cfg.get<string>('GOOGLE_CALLBACK_URL')!
        }
      : undefined,
    frontend: {
      origins: (cfg.get<string>('FRONTEND_ORIGINS') ?? '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
      defaultRedirectUrl: cfg.get<string>('FRONTEND_ORIGIN') ?? 'http://localhost:3000',
      resetUrlBase: cfg.get<string>('FRONTEND_RESET_URL') ?? ''
    }
  }),
  inject: [ConfigService]
});

@Module({
  imports: [AuthAdaptersModule, AuthMailerModule, ConfigModule, authKitModule],
  exports: [authKitModule, AuthAdaptersModule, AuthMailerModule]
})
export class AuthModule {}
```

The kit exports `AuthService`, strategies, guards, middleware, and DTOs. Inject
`AuthService` wherever you need to issue tokens manually.

## 4. Controllers & guards

Use the supplied guards in your own controllers or expose the built-in controller
from the kit. Example custom controller:

```ts
@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @UseGuards(LocalAuthGuard)
  @Post('login')
  async login(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const user = req.user as { id: number; username: string; role?: string | null };
    const token = await this.auth.issueAccessToken(user);
    res.cookie('accessToken', token, { httpOnly: true, sameSite: 'lax' });
    return { user, accessToken: token };
  }
}
```

## Required environment variables

| Variable | Description |
| --- | --- |
| `DATABASE_URL` | Connection string for your user/password-reset persistence |
| `JWT_SECRET` | Secret used to sign access tokens (min 16 chars recommended) |
| `JWT_EXPIRES_IN` | Token lifetime (`15m`, `1h`, etc.) |
| `AUTH_USE_COOKIE` | `true` to set JWT in an HttpOnly cookie |
| `COOKIE_CROSS_SITE` | `true` when API and frontend are on different domains (sets SameSite=None) |
| `COOKIE_DOMAIN` | Optional domain for cookies (e.g. `.example.com`) |
| `FRONTEND_ORIGIN` / `FRONTEND_ORIGINS` | Allowed origins for CORS/CSRF (comma separated) |
| `FRONTEND_RESET_URL` | Base URL for password reset link (e.g. `https://app/reset?token=`) |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID (optional if Google login disabled) |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `GOOGLE_CALLBACK_URL` | OAuth callback URL pointing back to your API |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `EMAIL_FROM` | SMTP configuration for password reset email (optional) |

## Google OAuth set-up

1. In [Google Cloud Console](https://console.cloud.google.com/apis/credentials), create an OAuth client ID (Web application).
2. Add your API callback URL (e.g. `https://api.example.com/auth/google/callback`).
3. Add your frontend origins (`https://app.example.com`).
4. Populate `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_CALLBACK_URL` in your environment.
5. Expose the `/auth/google` and `/auth/google/callback` routes using the guards provided by the kit or the default controller.

## Frontend integration

Default endpoints (assuming the packaged controller is used):

| Method | Route | Description |
| --- | --- | --- |
| `POST` | `/auth/login` | Local login; returns `{ user, accessToken, csrfToken }` (cookie set when enabled) |
| `POST` | `/auth/register` | Register a user and issue access token |
| `POST` | `/auth/logout` | Clear cookies (if cookie mode on) |
| `GET` | `/auth/csrf` | Obtain CSRF token for double-submit scheme |
| `GET` | `/auth/google` | Redirect to Google OAuth |
| `GET` | `/auth/google/callback` | Callback; redirects with state or sets cookies |
| `POST` | `/auth/password/forgot` | Trigger password reset flow |
| `POST` | `/auth/password/reset` | Complete password reset |

Frontend tips:

- When using cookies, issue requests with `credentials: 'include'`.
- In SPA flows, parse the redirected URL for `accessToken`/`csrfToken` when
  cookie mode is off.
- Retrieve `/auth/csrf` before protected POST requests to include the
  double-submit token in headers.

## Testing

- Unit-test your adapters to ensure they meet the contract.
- Add e2e tests that exercise local login, Google OAuth (or stub strategy), and
  password-reset flows.
- Mock SMTP or the mailer when running tests to avoid external calls.

## License

MIT © Derek
