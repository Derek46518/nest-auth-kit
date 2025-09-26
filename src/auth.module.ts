import { DynamicModule, Module, Provider } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

import { AuthService } from './auth.service';
import { LocalStrategy } from './local.strategy';
import { JwtStrategy } from './jwt.strategy';
import { GoogleStrategy } from './google.strategy';
import { AuthController } from './auth.controller';
import { CsrfMiddleware } from './csrf.middleware';
import { AUTH_MAILER, AUTH_MODULE_OPTIONS, AUTH_RESET_TOKEN_STORE, AUTH_USERS_SERVICE } from './internal/tokens';
import type { AuthModuleAsyncOptions, AuthModuleOptions } from './interfaces/options.interface';

@Module({})
export class AuthModule {
  static register(options: AuthModuleOptions): DynamicModule {
    const optionsProvider: Provider = { provide: AUTH_MODULE_OPTIONS, useValue: options };
    return this.buildModule(optionsProvider, options.imports ?? []);
  }

  static registerAsync(options: AuthModuleAsyncOptions): DynamicModule {
    const optionsProvider: Provider = {
      provide: AUTH_MODULE_OPTIONS,
      useFactory: options.useFactory,
      inject: options.inject ?? []
    };
    return this.buildModule(optionsProvider, options.imports ?? []);
  }

  private static buildModule(optionsProvider: Provider, extraImports: any[]): DynamicModule {
    class AuthOptionsHolderModule {}

    const optionsModule: DynamicModule = {
      module: AuthOptionsHolderModule,
      providers: [optionsProvider],
      exports: [optionsProvider]
    };

    const jwtModule = JwtModule.registerAsync({
      imports: [optionsModule],
      useFactory: (opts: AuthModuleOptions) => ({
        secret: opts.jwt.secret,
        signOptions: { expiresIn: opts.jwt.expiresIn ?? '15m' }
      }),
      inject: [AUTH_MODULE_OPTIONS]
    });

    const coreProviders: Provider[] = [
      AuthService,
      LocalStrategy,
      JwtStrategy,
      GoogleStrategy,
      CsrfMiddleware
    ];

    return {
      module: AuthModule,
      imports: [PassportModule.register({ session: false }), optionsModule, jwtModule, ...extraImports],
      controllers: [AuthController],
      providers: coreProviders,
      exports: [
        optionsModule,
        AuthService,
        LocalStrategy,
        JwtStrategy,
        GoogleStrategy,
        CsrfMiddleware,
        PassportModule,
        JwtModule
      ]
    };
  }
}
