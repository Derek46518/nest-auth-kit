import type { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import type { AuthModuleOptions } from './interfaces/options.interface';
export declare class AuthController {
    private readonly auth;
    private readonly opts;
    private readonly useCookie;
    private readonly cookieName;
    private readonly csrfCookie;
    private readonly csrfHeader;
    private readonly cookieDomain?;
    private readonly isCrossSite;
    private readonly secureCookies;
    private readonly maxAge;
    constructor(auth: AuthService, opts: AuthModuleOptions);
    private accessTokenCookieOptions;
    private csrfCookieOptions;
    private setAuthCookies;
    private clearAuthCookies;
    private buildRedirectUrl;
    login(res: Response, req: Request): Promise<{
        user: {
            id: number;
            username: string;
            role?: string | null;
        };
        accessToken: string;
        csrfToken: string | null;
    }>;
    register(dto: RegisterDto, res: Response): Promise<{
        user: import(".").AuthUser;
        accessToken: string;
        csrfToken: string | null;
    }>;
    me(req: Request): Express.User | undefined;
    logout(res: Response): Promise<{
        ok: boolean;
    }>;
    getCsrf(res: Response): {
        csrfToken: string;
    };
    googleAuth(): void;
    googleCallback(req: Request, res: Response): Promise<any>;
    forgotPassword(dto: ForgotPasswordDto): Promise<{
        ok: boolean;
    }>;
    resetPassword(dto: ResetPasswordDto): Promise<{
        ok: boolean;
    }>;
}
