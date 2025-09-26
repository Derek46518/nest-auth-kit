import { AuthUser } from './auth-user.interface';
export interface AuthUsersService {
    /** Validate username/email + password and return safe user when success. */
    validateCredentials(identifier: string, password: string): Promise<AuthUser | null>;
    /** Create a new local account and return safe user payload. */
    registerUser(username: string, password: string, email: string): Promise<AuthUser>;
    /** Find user by email (case-insensitive if relevant). */
    findByEmail(email: string): Promise<AuthUser | null>;
    /** Create or reuse an account for OAuth users. */
    createOAuthUser(email: string, usernameBase: string): Promise<AuthUser>;
    /** Update password for user id (already validated externally). */
    updatePassword(userId: number, newPassword: string): Promise<void>;
}
