"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CsrfMiddleware = void 0;
const common_1 = require("@nestjs/common");
const tokens_1 = require("./internal/tokens");
const SAFE = new Set(['GET', 'HEAD', 'OPTIONS']);
function fallbackOrigins() {
    return [/^https?:\/\/localhost:\d+$/, /^https?:\/\/127\.0\.0\.1:\d+$/];
}
function buildAllowed(opts) {
    var _a, _b;
    const configured = (_b = (_a = opts.frontend) === null || _a === void 0 ? void 0 : _a.origins) !== null && _b !== void 0 ? _b : [];
    if (!configured.length)
        return fallbackOrigins();
    const res = [];
    for (const origin of configured) {
        try {
            const u = new URL(origin);
            const host = u.host.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const proto = u.protocol.replace(':', '');
            res.push(new RegExp(`^${proto}:\/\/${host}$`));
        }
        catch {
            // ignore invalid entries
        }
    }
    return res.length ? res : fallbackOrigins();
}
function readCookies(req) {
    var _a;
    const existing = req.cookies;
    if (existing && typeof existing === 'object')
        return existing;
    const header = (_a = req.headers) === null || _a === void 0 ? void 0 : _a.cookie;
    if (!header)
        return {};
    const cookies = {};
    for (const part of header.split(';')) {
        const [rawKey, ...rest] = part.split('=');
        if (!rawKey)
            continue;
        const key = rawKey.trim();
        const value = rest.join('=').trim();
        if (!key)
            continue;
        cookies[key] = decodeURIComponent(value !== null && value !== void 0 ? value : '');
    }
    req.cookies = cookies;
    return cookies;
}
let CsrfMiddleware = class CsrfMiddleware {
    constructor(opts) {
        var _a, _b, _c, _d;
        this.opts = opts;
        this.allowed = buildAllowed(opts);
        this.csrfHeader = (_b = (_a = opts.cookies) === null || _a === void 0 ? void 0 : _a.csrfHeaderName) !== null && _b !== void 0 ? _b : 'x-csrf-token';
        this.csrfCookie = (_d = (_c = opts.cookies) === null || _c === void 0 ? void 0 : _c.csrfCookieName) !== null && _d !== void 0 ? _d : 'csrfToken';
    }
    use(req, _res, next) {
        if (SAFE.has(req.method))
            return next();
        const origin = req.get('origin') || '';
        const referer = req.get('referer') || '';
        const isBrowserLike = Boolean(origin || referer);
        if (isBrowserLike) {
            const okOrigin = this.allowed.some((regex) => regex.test(origin) || regex.test(referer));
            if (!okOrigin)
                throw new common_1.ForbiddenException('Bad Origin');
        }
        const hdr = req.get(this.csrfHeader);
        const cookie = readCookies(req)[this.csrfCookie];
        if (isBrowserLike) {
            if (!hdr || !cookie || hdr !== cookie) {
                throw new common_1.ForbiddenException('Invalid CSRF token');
            }
        }
        next();
    }
};
exports.CsrfMiddleware = CsrfMiddleware;
exports.CsrfMiddleware = CsrfMiddleware = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, common_1.Inject)(tokens_1.AUTH_MODULE_OPTIONS)),
    __metadata("design:paramtypes", [Object])
], CsrfMiddleware);
