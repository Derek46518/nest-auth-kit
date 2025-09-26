import { NestMiddleware } from '@nestjs/common';
import type { Request, Response, NextFunction } from 'express';
import type { AuthModuleOptions } from './interfaces/options.interface';
export declare class CsrfMiddleware implements NestMiddleware {
    private readonly opts;
    private readonly allowed;
    private readonly csrfHeader;
    private readonly csrfCookie;
    constructor(opts: AuthModuleOptions);
    use(req: Request, _res: Response, next: NextFunction): void;
}
