export interface AuthUser {
    id: number;
    username: string;
    email: string | null;
    role?: string;
}
export type AuthRole = string;
export interface AuthUserWithRole extends AuthUser {
    role: string;
}
