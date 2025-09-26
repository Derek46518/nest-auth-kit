import { DynamicModule } from '@nestjs/common';
import type { AuthModuleAsyncOptions, AuthModuleOptions } from './interfaces/options.interface';
export declare class AuthModule {
    static register(options: AuthModuleOptions): DynamicModule;
    static registerAsync(options: AuthModuleAsyncOptions): DynamicModule;
    private static buildModule;
}
