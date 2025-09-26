export interface PasswordResetTokenRecord {
  id: number;
  userId: number;
  tokenHash: string;
  expiresAt: Date;
  usedAt?: Date | null;
}

export interface PasswordResetTokenStore {
  saveToken(userId: number, tokenHash: string, expiresAt: Date): Promise<void>;
  findByHash(tokenHash: string): Promise<PasswordResetTokenRecord | null>;
  markUsed(id: number, usedAt: Date): Promise<void>;
}
