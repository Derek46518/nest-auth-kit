import type { DynamicModule, ForwardReference, Type } from '@nestjs/common';
export type InjectionToken<T = any> = string | symbol | Type<T>;
export interface AuthCookieOptions {
    useCookies?: boolean;
    cookieName?: string;
    csrfCookieName?: string;
    csrfHeaderName?: string;
    cookieDomain?: string;
    crossSite?: boolean;
    secureCookies?: boolean;
    maxAgeMs?: number;
}
export interface GoogleOAuthOptions {
    clientID: string;
    clientSecret: string;
    callbackURL: string;
    scope?: string[];
}
export interface FrontendOptions {
    /** Allowed origins used for CSRF + cookie responses. */
    origins?: string[];
    /** Default URL to redirect to after OAuth login when state missing. */
    defaultRedirectUrl?: string;
    /** Base URL used to build password reset links (e.g. https://app/reset?token=). */
    resetUrlBase?: string;
}
export interface AuthModuleOptions {
    /** Ensure underlying services are provided by imported modules. */
    imports?: Array<Type<any> | DynamicModule | Promise<DynamicModule> | ForwardReference>;
    /** Injection token for the users service adapter. */
    userServiceToken: InjectionToken;
    /** Injection token for password reset token persistence. */
    resetTokenStoreToken: InjectionToken;
    /** Optional injection token for transactional mailer. */
    mailerToken?: InjectionToken;
    /** Options passed to JwtModule.register. */
    jwt: {
        secret: string;
        expiresIn?: string | number;
    };
    /** Cookie configuration used by controller/strategies. */
    cookies?: AuthCookieOptions;
    /** Google OAuth settings (optional). */
    google?: GoogleOAuthOptions;
    /** Known frontend metadata (origins + fallback redirect). */
    frontend?: FrontendOptions;
}
export interface AuthModuleAsyncOptions extends Pick<AuthModuleOptions, 'imports'> {
    useFactory: (...args: any[]) => Promise<AuthModuleOptions> | AuthModuleOptions;
    inject?: any[];
}
