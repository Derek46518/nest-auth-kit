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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthController = void 0;
const common_1 = require("@nestjs/common");
const node_crypto_1 = __importDefault(require("node:crypto"));
const auth_service_1 = require("./auth.service");
const register_dto_1 = require("./dto/register.dto");
const forgot_password_dto_1 = require("./dto/forgot-password.dto");
const reset_password_dto_1 = require("./dto/reset-password.dto");
const guards_1 = require("./guards");
const tokens_1 = require("./internal/tokens");
let AuthController = class AuthController {
    constructor(auth, opts) {
        var _a, _b, _c, _d, _e, _f, _g, _h;
        this.auth = auth;
        this.opts = opts;
        const cookies = (_a = opts.cookies) !== null && _a !== void 0 ? _a : {};
        this.useCookie = (_b = cookies.useCookies) !== null && _b !== void 0 ? _b : true;
        this.cookieName = (_c = cookies.cookieName) !== null && _c !== void 0 ? _c : 'accessToken';
        this.csrfCookie = (_d = cookies.csrfCookieName) !== null && _d !== void 0 ? _d : 'csrfToken';
        this.csrfHeader = (_e = cookies.csrfHeaderName) !== null && _e !== void 0 ? _e : 'x-csrf-token';
        this.cookieDomain = cookies.cookieDomain;
        const crossSite = (_f = cookies.crossSite) !== null && _f !== void 0 ? _f : false;
        this.isCrossSite = crossSite;
        this.secureCookies = (_g = cookies.secureCookies) !== null && _g !== void 0 ? _g : crossSite;
        this.maxAge = (_h = cookies.maxAgeMs) !== null && _h !== void 0 ? _h : 60 * 60 * 1000;
    }
    accessTokenCookieOptions() {
        return {
            httpOnly: true,
            secure: this.secureCookies,
            sameSite: this.isCrossSite ? 'none' : 'lax',
            maxAge: this.maxAge,
            path: '/',
            domain: this.cookieDomain
        };
    }
    csrfCookieOptions() {
        return {
            httpOnly: false,
            secure: this.secureCookies,
            sameSite: this.isCrossSite ? 'none' : 'lax',
            maxAge: this.maxAge,
            path: '/',
            domain: this.cookieDomain
        };
    }
    setAuthCookies(res, accessToken) {
        res.cookie(this.cookieName, accessToken, this.accessTokenCookieOptions());
        const csrfToken = node_crypto_1.default.randomBytes(32).toString('base64url');
        res.cookie(this.csrfCookie, csrfToken, this.csrfCookieOptions());
        return csrfToken;
    }
    clearAuthCookies(res) {
        const opts = {
            path: '/',
            domain: this.cookieDomain,
            sameSite: this.isCrossSite ? 'none' : 'lax',
            secure: this.secureCookies
        };
        res.clearCookie(this.cookieName, opts);
        res.clearCookie(this.csrfCookie, opts);
    }
    buildRedirectUrl(state) {
        var _a, _b, _c, _d;
        const fallback = (_b = (_a = this.opts.frontend) === null || _a === void 0 ? void 0 : _a.defaultRedirectUrl) !== null && _b !== void 0 ? _b : 'http://localhost:3000';
        const origins = (_d = (_c = this.opts.frontend) === null || _c === void 0 ? void 0 : _c.origins) !== null && _d !== void 0 ? _d : [];
        const allowed = origins.length ? origins : [fallback];
        if (!state)
            return fallback;
        try {
            const parsed = JSON.parse(Buffer.from(state, 'base64url').toString('utf8'));
            const url = parsed === null || parsed === void 0 ? void 0 : parsed.redirect;
            if (!url)
                return fallback;
            const target = new URL(url);
            const isAllowed = allowed.some((origin) => {
                try {
                    const ref = new URL(origin);
                    return ref.protocol === target.protocol && ref.host === target.host;
                }
                catch {
                    return false;
                }
            });
            return isAllowed ? url : fallback;
        }
        catch {
            return fallback;
        }
    }
    async login(res, req) {
        var _a;
        const user = req.user;
        const accessToken = await this.auth.issueAccessToken({ id: user.id, username: user.username, role: (_a = user.role) !== null && _a !== void 0 ? _a : null });
        const csrfToken = this.useCookie ? this.setAuthCookies(res, accessToken) : null;
        if (!this.useCookie) {
            res.setHeader(this.csrfHeader, csrfToken !== null && csrfToken !== void 0 ? csrfToken : '');
        }
        return { user, accessToken, csrfToken };
    }
    async register(dto, res) {
        const { user, accessToken } = await this.auth.register(dto);
        const csrfToken = this.useCookie ? this.setAuthCookies(res, accessToken) : null;
        if (!this.useCookie) {
            res.setHeader(this.csrfHeader, csrfToken !== null && csrfToken !== void 0 ? csrfToken : '');
        }
        return { user, accessToken, csrfToken };
    }
    me(req) {
        return req.user;
    }
    async logout(res) {
        this.clearAuthCookies(res);
        return { ok: true };
    }
    getCsrf(res) {
        const token = node_crypto_1.default.randomBytes(32).toString('base64url');
        res.cookie(this.csrfCookie, token, this.csrfCookieOptions());
        return { csrfToken: token };
    }
    googleAuth() {
        // handled by passport
    }
    async googleCallback(req, res) {
        var _a, _b;
        const user = req.user;
        const accessToken = await this.auth.issueAccessToken({ id: user.id, username: user.username, role: (_a = user.role) !== null && _a !== void 0 ? _a : null });
        const csrfToken = this.useCookie ? this.setAuthCookies(res, accessToken) : null;
        const state = typeof ((_b = req.query) === null || _b === void 0 ? void 0 : _b.state) === 'string' ? req.query.state : undefined;
        let redirectUrl = this.buildRedirectUrl(state);
        if (!this.useCookie) {
            try {
                const url = new URL(redirectUrl);
                url.searchParams.set('accessToken', accessToken);
                if (csrfToken)
                    url.searchParams.set('csrfToken', String(csrfToken));
                redirectUrl = url.toString();
            }
            catch {
                return { user, accessToken, csrfToken };
            }
        }
        res.redirect(302, redirectUrl);
        return undefined;
    }
    async forgotPassword(dto) {
        await this.auth.createPasswordResetToken(dto.email);
        return { ok: true };
    }
    async resetPassword(dto) {
        await this.auth.resetPassword(dto.token, dto.password);
        return { ok: true };
    }
};
exports.AuthController = AuthController;
__decorate([
    (0, common_1.UseGuards)(guards_1.LocalAuthGuard),
    (0, common_1.Post)('login'),
    (0, common_1.HttpCode)(200),
    (0, common_1.Header)('Cache-Control', 'no-store'),
    __param(0, (0, common_1.Res)({ passthrough: true })),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "login", null);
__decorate([
    (0, common_1.Post)('register'),
    (0, common_1.HttpCode)(201),
    (0, common_1.Header)('Cache-Control', 'no-store'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Res)({ passthrough: true })),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [register_dto_1.RegisterDto, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "register", null);
__decorate([
    (0, common_1.UseGuards)(guards_1.JwtAuthGuard),
    (0, common_1.Get)('me'),
    (0, common_1.Header)('Cache-Control', 'no-store'),
    __param(0, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "me", null);
__decorate([
    (0, common_1.Post)('logout'),
    (0, common_1.HttpCode)(200),
    __param(0, (0, common_1.Res)({ passthrough: true })),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "logout", null);
__decorate([
    (0, common_1.Get)('csrf'),
    (0, common_1.HttpCode)(200),
    (0, common_1.Header)('Cache-Control', 'no-store'),
    __param(0, (0, common_1.Res)({ passthrough: true })),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "getCsrf", null);
__decorate([
    (0, common_1.UseGuards)(guards_1.GoogleAuthWithStateGuard),
    (0, common_1.Get)('google'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", void 0)
], AuthController.prototype, "googleAuth", null);
__decorate([
    (0, common_1.UseGuards)(guards_1.GoogleAuthGuard),
    (0, common_1.Get)('google/callback'),
    (0, common_1.Header)('Cache-Control', 'no-store'),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, common_1.Res)({ passthrough: true })),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "googleCallback", null);
__decorate([
    (0, common_1.Post)('password/forgot'),
    (0, common_1.HttpCode)(200),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [forgot_password_dto_1.ForgotPasswordDto]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "forgotPassword", null);
__decorate([
    (0, common_1.Post)('password/reset'),
    (0, common_1.HttpCode)(200),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [reset_password_dto_1.ResetPasswordDto]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "resetPassword", null);
exports.AuthController = AuthController = __decorate([
    (0, common_1.Controller)('auth'),
    __param(1, (0, common_1.Inject)(tokens_1.AUTH_MODULE_OPTIONS)),
    __metadata("design:paramtypes", [auth_service_1.AuthService, Object])
], AuthController);
