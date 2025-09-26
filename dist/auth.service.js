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
exports.AuthService = void 0;
const common_1 = require("@nestjs/common");
const jwt_1 = require("@nestjs/jwt");
const node_crypto_1 = __importDefault(require("node:crypto"));
const tokens_1 = require("./internal/tokens");
let AuthService = class AuthService {
    constructor(users, jwt, resetStore, mailer, opts) {
        this.users = users;
        this.jwt = jwt;
        this.resetStore = resetStore;
        this.mailer = mailer;
        this.opts = opts;
    }
    hashToken(token) {
        return node_crypto_1.default.createHash('sha256').update(token).digest('hex');
    }
    async validateUser(identifier, password) {
        const user = await this.users.validateCredentials(identifier, password);
        if (!user)
            throw new common_1.UnauthorizedException('Invalid credentials');
        return user;
    }
    async issueAccessToken(user) {
        var _a;
        return this.jwt.signAsync({
            sub: user.id,
            username: user.username,
            role: (_a = user.role) !== null && _a !== void 0 ? _a : null
        });
    }
    async register(dto) {
        const user = await this.users.registerUser(dto.username, dto.password, dto.email);
        const accessToken = await this.issueAccessToken({ id: user.id, username: user.username, role: user.role });
        return { user, accessToken };
    }
    async loginWithCredentials(identifier, password) {
        const user = await this.validateUser(identifier, password);
        const accessToken = await this.issueAccessToken({ id: user.id, username: user.username, role: user.role });
        return { user, accessToken };
    }
    async loginWithGoogleProfile(profile) {
        var _a, _b, _c;
        const email = (_b = (_a = profile.emails) === null || _a === void 0 ? void 0 : _a[0]) === null || _b === void 0 ? void 0 : _b.value;
        const displayName = profile.displayName || ((_c = profile.name) === null || _c === void 0 ? void 0 : _c.givenName) || 'user';
        if (!email)
            throw new common_1.UnauthorizedException('Google account has no email');
        const existed = await this.users.findByEmail(email);
        let user;
        if (existed) {
            user = existed;
        }
        else {
            const base = (displayName || email.split('@')[0]).replace(/\s+/g, '').slice(0, 20) || 'user';
            user = await this.users.createOAuthUser(email, base);
        }
        const accessToken = await this.issueAccessToken({
            id: user.id,
            username: user.username,
            role: user.role
        });
        return { user, accessToken };
    }
    async createPasswordResetToken(email) {
        var _a, _b;
        const user = await this.users.findByEmail(email);
        if (!user)
            return { ok: true };
        const token = node_crypto_1.default.randomBytes(32).toString('base64url');
        const tokenHash = this.hashToken(token);
        const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
        await this.resetStore.saveToken(user.id, tokenHash, expiresAt);
        const resetBase = (_b = (_a = this.opts.frontend) === null || _a === void 0 ? void 0 : _a.resetUrlBase) !== null && _b !== void 0 ? _b : '';
        const link = resetBase ? `${resetBase}${token}` : token;
        if (this.mailer && this.mailer.isEnabled() && user.email) {
            const subject = 'Password Reset';
            const html = `<p>You requested a password reset.</p><p>Click the link to reset: <a href=\"${link}\">${link}</a></p><p>If you did not request this, you can ignore this email.</p>`;
            try {
                await this.mailer.send(user.email, subject, html, `Reset link: ${link}`);
            }
            catch {
                // swallow mailer errors to avoid leaking user existence
            }
        }
        return { ok: true };
    }
    async resetPassword(token, newPassword) {
        const tokenHash = this.hashToken(token);
        const record = await this.resetStore.findByHash(tokenHash);
        if (!record)
            throw new common_1.NotFoundException('Invalid token');
        if (record.usedAt)
            throw new common_1.BadRequestException('Token already used');
        if (record.expiresAt.getTime() < Date.now())
            throw new common_1.BadRequestException('Token expired');
        await this.users.updatePassword(record.userId, newPassword);
        await this.resetStore.markUsed(record.id, new Date());
        return { ok: true };
    }
};
exports.AuthService = AuthService;
exports.AuthService = AuthService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, common_1.Inject)(tokens_1.AUTH_USERS_SERVICE)),
    __param(2, (0, common_1.Inject)(tokens_1.AUTH_RESET_TOKEN_STORE)),
    __param(3, (0, common_1.Optional)()),
    __param(3, (0, common_1.Inject)(tokens_1.AUTH_MAILER)),
    __param(4, (0, common_1.Inject)(tokens_1.AUTH_MODULE_OPTIONS)),
    __metadata("design:paramtypes", [Object, jwt_1.JwtService, Object, Object, Object])
], AuthService);
