export interface EmailMessage {
  to: string;
  subject: string;
  text: string;
  html?: string;
  replyTo?: string;
  /** Stable key for de-duplication of the same logical email. */
  dedupeKey?: string;
}

export interface EmailSendResult {
  providerMessageId?: string;
  providerName: string;
}

export interface EmailProvider {
  readonly name: string;
  send(message: EmailMessage): Promise<EmailSendResult>;
}
