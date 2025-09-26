import { Strategy } from 'passport-jwt';
import type { AuthModuleOptions } from './interfaces/options.interface';
interface JwtPayload {
    sub: number;
    username: string;
    role?: string | null;
}
declare const JwtStrategy_base: new (...args: [opt: import("passport-jwt").StrategyOptionsWithoutRequest] | [opt: import("passport-jwt").StrategyOptionsWithRequest]) => Strategy & {
    validate(...args: any[]): unknown;
};
export declare class JwtStrategy extends JwtStrategy_base {
    private readonly opts;
    constructor(opts: AuthModuleOptions);
    validate(payload: JwtPayload): Promise<{
        userId: number;
        username: string;
        role: string | null;
    }>;
}
export {};
