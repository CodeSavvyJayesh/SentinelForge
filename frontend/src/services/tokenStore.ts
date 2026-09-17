/**
 * The access token lives here: a module variable, never localStorage.
 *
 * Anything written to localStorage can be read by injected JavaScript, so a
 * single XSS bug would leak the token. Keeping it in memory means a page
 * reload loses it — the app silently asks /auth/refresh for a new one using
 * the httpOnly cookie, which scripts cannot read at all.
 */

let accessToken: string | null = null

export const tokenStore = {
  get(): string | null {
    return accessToken
  },
  set(token: string | null): void {
    accessToken = token
  },
  clear(): void {
    accessToken = null
  },
}
