import { ForbiddenException, Injectable, NestMiddleware, Inject } from '@nestjs/common';
import type { Request, Response, NextFunction } from 'express';

import { AUTH_MODULE_OPTIONS } from './internal/tokens';
import type { AuthModuleOptions } from './interfaces/options.interface';

const SAFE = new Set(['GET', 'HEAD', 'OPTIONS']);

function fallbackOrigins() {
  return [/^https?:\/\/localhost:\d+$/, /^https?:\/\/127\.0\.0\.1:\d+$/];
}

function buildAllowed(opts: AuthModuleOptions): RegExp[] {
  const configured = opts.frontend?.origins ?? [];
  if (!configured.length) return fallbackOrigins();

  const res: RegExp[] = [];
  for (const origin of configured) {
    try {
      const u = new URL(origin);
      const host = u.host.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const proto = u.protocol.replace(':', '');
      res.push(new RegExp(`^${proto}:\/\/${host}$`));
    } catch {
      // ignore invalid entries
    }
  }
  return res.length ? res : fallbackOrigins();
}

function readCookies(req: Request): Record<string, string> {
  const existing = (req as any).cookies;
  if (existing && typeof existing === 'object') return existing;
  const header = req.headers?.cookie;
  if (!header) return {};
  const cookies: Record<string, string> = {};
  for (const part of header.split(';')) {
    const [rawKey, ...rest] = part.split('=');
    if (!rawKey) continue;
    const key = rawKey.trim();
    const value = rest.join('=').trim();
    if (!key) continue;
    cookies[key] = decodeURIComponent(value ?? '');
  }
  (req as any).cookies = cookies;
  return cookies;
}

@Injectable()
export class CsrfMiddleware implements NestMiddleware {
  private readonly allowed: RegExp[];
  private readonly csrfHeader: string;
  private readonly csrfCookie: string;

  constructor(@Inject(AUTH_MODULE_OPTIONS) private readonly opts: AuthModuleOptions) {
    this.allowed = buildAllowed(opts);
    this.csrfHeader = opts.cookies?.csrfHeaderName ?? 'x-csrf-token';
    this.csrfCookie = opts.cookies?.csrfCookieName ?? 'csrfToken';
  }

  use(req: Request, _res: Response, next: NextFunction) {
    if (SAFE.has(req.method)) return next();

    const origin = req.get('origin') || '';
    const referer = req.get('referer') || '';
    const isBrowserLike = Boolean(origin || referer);

    if (isBrowserLike) {
      const okOrigin = this.allowed.some((regex) => regex.test(origin) || regex.test(referer));
      if (!okOrigin) throw new ForbiddenException('Bad Origin');
    }

    const hdr = req.get(this.csrfHeader);
    const cookie = readCookies(req)[this.csrfCookie];
    if (isBrowserLike) {
      if (!hdr || !cookie || hdr !== cookie) {
        throw new ForbiddenException('Invalid CSRF token');
      }
    }

    next();
  }
}
