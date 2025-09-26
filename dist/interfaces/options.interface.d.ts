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
    origins?: string[];
    defaultRedirectUrl?: string;
    resetUrlBase?: string;
}
export interface AuthModuleOptions {
    imports?: Array<Type<any> | DynamicModule | Promise<DynamicModule> | ForwardReference>;
    userServiceToken: InjectionToken;
    resetTokenStoreToken: InjectionToken;
    mailerToken?: InjectionToken;
    jwt: {
        secret: string;
        expiresIn?: string | number;
    };
    cookies?: AuthCookieOptions;
    google?: GoogleOAuthOptions;
    frontend?: FrontendOptions;
}
export interface AuthModuleAsyncOptions extends Pick<AuthModuleOptions, 'imports'> {
    useFactory: (...args: any[]) => Promise<AuthModuleOptions> | AuthModuleOptions;
    inject?: any[];
}
