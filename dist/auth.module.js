"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var AuthModule_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthModule = void 0;
const common_1 = require("@nestjs/common");
const jwt_1 = require("@nestjs/jwt");
const passport_1 = require("@nestjs/passport");
const auth_service_1 = require("./auth.service");
const local_strategy_1 = require("./local.strategy");
const jwt_strategy_1 = require("./jwt.strategy");
const google_strategy_1 = require("./google.strategy");
const auth_controller_1 = require("./auth.controller");
const csrf_middleware_1 = require("./csrf.middleware");
const tokens_1 = require("./internal/tokens");
let AuthModule = AuthModule_1 = class AuthModule {
    static register(options) {
        var _a;
        const optionsProvider = { provide: tokens_1.AUTH_MODULE_OPTIONS, useValue: options };
        return this.buildModule(optionsProvider, (_a = options.imports) !== null && _a !== void 0 ? _a : []);
    }
    static registerAsync(options) {
        var _a, _b;
        const optionsProvider = {
            provide: tokens_1.AUTH_MODULE_OPTIONS,
            useFactory: options.useFactory,
            inject: (_a = options.inject) !== null && _a !== void 0 ? _a : []
        };
        return this.buildModule(optionsProvider, (_b = options.imports) !== null && _b !== void 0 ? _b : []);
    }
    static buildModule(optionsProvider, extraImports) {
        class AuthOptionsHolderModule {
        }
        const optionsModule = {
            module: AuthOptionsHolderModule,
            providers: [optionsProvider],
            exports: [optionsProvider]
        };
        const jwtModule = jwt_1.JwtModule.registerAsync({
            imports: [optionsModule],
            useFactory: (opts) => {
                var _a;
                return ({
                    secret: opts.jwt.secret,
                    signOptions: { expiresIn: (_a = opts.jwt.expiresIn) !== null && _a !== void 0 ? _a : '15m' }
                });
            },
            inject: [tokens_1.AUTH_MODULE_OPTIONS]
        });
        const coreProviders = [
            auth_service_1.AuthService,
            local_strategy_1.LocalStrategy,
            jwt_strategy_1.JwtStrategy,
            google_strategy_1.GoogleStrategy,
            csrf_middleware_1.CsrfMiddleware
        ];
        return {
            module: AuthModule_1,
            imports: [passport_1.PassportModule.register({ session: false }), optionsModule, jwtModule, ...extraImports],
            controllers: [auth_controller_1.AuthController],
            providers: coreProviders,
            exports: [
                optionsModule,
                auth_service_1.AuthService,
                local_strategy_1.LocalStrategy,
                jwt_strategy_1.JwtStrategy,
                google_strategy_1.GoogleStrategy,
                csrf_middleware_1.CsrfMiddleware,
                passport_1.PassportModule,
                jwt_1.JwtModule
            ]
        };
    }
};
exports.AuthModule = AuthModule;
exports.AuthModule = AuthModule = AuthModule_1 = __decorate([
    (0, common_1.Module)({})
], AuthModule);
