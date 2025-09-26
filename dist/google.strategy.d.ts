import { Profile, VerifyCallback } from 'passport-google-oauth20';
import { AuthService } from './auth.service';
import type { AuthModuleOptions } from './interfaces/options.interface';
declare const GoogleStrategy_base: new (...args: any) => any;
export declare class GoogleStrategy extends GoogleStrategy_base {
    private readonly auth;
    constructor(opts: AuthModuleOptions, auth: AuthService);
    validate(_accessToken: string, _refreshToken: string, profile: Profile, done: VerifyCallback): Promise<any>;
}
export {};
