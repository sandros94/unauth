export interface SessionData {
  user: string;
  /** The provider the user signed in with; absent for a password login. */
  provider?: string;
}
