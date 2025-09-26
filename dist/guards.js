"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.GoogleAuthWithStateGuard = exports.GoogleAuthGuard = exports.JwtAuthGuard = exports.LocalAuthGuard = void 0;
const common_1 = require("@nestjs/common");
const passport_1 = require("@nestjs/passport");
let LocalAuthGuard = class LocalAuthGuard extends (0, passport_1.AuthGuard)('local') {
};
exports.LocalAuthGuard = LocalAuthGuard;
exports.LocalAuthGuard = LocalAuthGuard = __decorate([
    (0, common_1.Injectable)()
], LocalAuthGuard);
let JwtAuthGuard = class JwtAuthGuard extends (0, passport_1.AuthGuard)('jwt') {
};
exports.JwtAuthGuard = JwtAuthGuard;
exports.JwtAuthGuard = JwtAuthGuard = __decorate([
    (0, common_1.Injectable)()
], JwtAuthGuard);
let GoogleAuthGuard = class GoogleAuthGuard extends (0, passport_1.AuthGuard)('google') {
};
exports.GoogleAuthGuard = GoogleAuthGuard;
exports.GoogleAuthGuard = GoogleAuthGuard = __decorate([
    (0, common_1.Injectable)()
], GoogleAuthGuard);
let GoogleAuthWithStateGuard = class GoogleAuthWithStateGuard extends (0, passport_1.AuthGuard)('google') {
    getAuthenticateOptions(context) {
        var _a;
        const req = context.switchToHttp().getRequest();
        const redirect = typeof ((_a = req.query) === null || _a === void 0 ? void 0 : _a.redirect) === 'string' ? req.query.redirect : undefined;
        let state;
        if (redirect) {
            try {
                state = Buffer.from(JSON.stringify({ redirect }), 'utf8').toString('base64url');
            }
            catch {
                // ignore encoding errors
            }
        }
        return state ? { state } : {};
    }
};
exports.GoogleAuthWithStateGuard = GoogleAuthWithStateGuard;
exports.GoogleAuthWithStateGuard = GoogleAuthWithStateGuard = __decorate([
    (0, common_1.Injectable)()
], GoogleAuthWithStateGuard);
