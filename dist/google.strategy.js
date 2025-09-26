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
exports.GoogleStrategy = void 0;
const common_1 = require("@nestjs/common");
const passport_1 = require("@nestjs/passport");
const passport_google_oauth20_1 = require("passport-google-oauth20");
const auth_service_1 = require("./auth.service");
const tokens_1 = require("./internal/tokens");
let GoogleStrategy = class GoogleStrategy extends (0, passport_1.PassportStrategy)(passport_google_oauth20_1.Strategy, 'google') {
    constructor(opts, auth) {
        const google = opts.google ?? {
            clientID: 'missing',
            clientSecret: 'missing',
            callbackURL: 'http://localhost:3000/auth/google/callback'
        };
        super({
            clientID: google.clientID || 'missing',
            clientSecret: google.clientSecret || 'missing',
            callbackURL: google.callbackURL || 'http://localhost:3000/auth/google/callback',
            scope: google.scope ?? ['profile', 'email']
        });
        this.auth = auth;
    }
    async validate(_accessToken, _refreshToken, profile, done) {
        try {
            const result = await this.auth.loginWithGoogleProfile(profile);
            return done(null, result.user);
        }
        catch (err) {
            return done(err);
        }
    }
};
exports.GoogleStrategy = GoogleStrategy;
exports.GoogleStrategy = GoogleStrategy = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, common_1.Inject)(tokens_1.AUTH_MODULE_OPTIONS)),
    __metadata("design:paramtypes", [Object, auth_service_1.AuthService])
], GoogleStrategy);
