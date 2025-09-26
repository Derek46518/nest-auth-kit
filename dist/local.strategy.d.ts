import { Strategy } from 'passport-local';
import { AuthService } from './auth.service';
declare const LocalStrategy_base: new (...args: [] | [options: import("passport-local").IStrategyOptionsWithRequest] | [options: import("passport-local").IStrategyOptions]) => Strategy & {
    validate(...args: any[]): unknown;
};
export declare class LocalStrategy extends LocalStrategy_base {
    private readonly auth;
    constructor(auth: AuthService);
    validate(req: any, username: string, password: string): Promise<import(".").AuthUser>;
}
export {};
