export interface AuthMailer {
    isEnabled(): boolean;
    send(to: string, subject: string, html: string, text?: string): Promise<void | boolean>;
}
