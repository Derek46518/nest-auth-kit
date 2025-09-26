import { ExecutionContext } from '@nestjs/common';
declare const LocalAuthGuard_base: import("@nestjs/passport").Type<import("@nestjs/passport").IAuthGuard>;
export declare class LocalAuthGuard extends LocalAuthGuard_base {
}
declare const JwtAuthGuard_base: import("@nestjs/passport").Type<import("@nestjs/passport").IAuthGuard>;
export declare class JwtAuthGuard extends JwtAuthGuard_base {
}
declare const GoogleAuthGuard_base: import("@nestjs/passport").Type<import("@nestjs/passport").IAuthGuard>;
export declare class GoogleAuthGuard extends GoogleAuthGuard_base {
}
declare const GoogleAuthWithStateGuard_base: import("@nestjs/passport").Type<import("@nestjs/passport").IAuthGuard>;
export declare class GoogleAuthWithStateGuard extends GoogleAuthWithStateGuard_base {
    getAuthenticateOptions(context: ExecutionContext): {
        state: string;
    } | {
        state?: undefined;
    };
}
export {};
