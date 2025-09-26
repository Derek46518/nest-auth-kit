import { AuthService } from './auth.service';
declare const LocalStrategy_base: new (...args: any) => any;
export declare class LocalStrategy extends LocalStrategy_base {
    private readonly auth;
    constructor(auth: AuthService);
    validate(req: any, username: string, password: string): Promise<import(".").AuthUser>;
}
export {};
