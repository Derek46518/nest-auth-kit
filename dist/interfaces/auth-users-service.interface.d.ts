import { AuthUser } from './auth-user.interface';
export interface AuthUsersService {
    validateCredentials(identifier: string, password: string): Promise<AuthUser | null>;
    registerUser(username: string, password: string, email: string): Promise<AuthUser>;
    findByEmail(email: string): Promise<AuthUser | null>;
    createOAuthUser(email: string, usernameBase: string): Promise<AuthUser>;
    updatePassword(userId: number, newPassword: string): Promise<void>;
}
