export interface SessionData {
  userId: string;
  provider: string;
  subject: string;
  name?: string;
  signedInAt: number;
}
