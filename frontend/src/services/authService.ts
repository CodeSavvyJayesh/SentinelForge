import type { ApiClient } from './apiClient'
import type { LoginInput, RegisterInput, TokenResponse, User } from '../types/auth'

export const AUTH_PATHS = {
  register: '/api/v1/auth/register',
  login: '/api/v1/auth/login',
  refresh: '/api/v1/auth/refresh',
  logout: '/api/v1/auth/logout',
  me: '/api/v1/auth/me',
} as const

export interface AuthService {
  register(input: RegisterInput): Promise<User>
  login(input: LoginInput): Promise<TokenResponse>
  /** Exchanges the httpOnly refresh cookie for a fresh access token. */
  refresh(signal?: AbortSignal): Promise<TokenResponse>
  logout(): Promise<void>
  me(): Promise<User>
}

export function createAuthService(client: ApiClient): AuthService {
  return {
    async register(input) {
      const result = await client.request<User>(AUTH_PATHS.register, {
        method: 'POST',
        body: input,
      })
      return result.data
    },

    async login(input) {
      const result = await client.request<TokenResponse>(AUTH_PATHS.login, {
        method: 'POST',
        body: input,
        withCredentials: true, // lets the browser store the refresh cookie
      })
      return result.data
    },

    async refresh(signal) {
      const result = await client.request<TokenResponse>(AUTH_PATHS.refresh, {
        method: 'POST',
        withCredentials: true,
        csrf: true,
        signal,
      })
      return result.data
    },

    async logout() {
      await client.request<null>(AUTH_PATHS.logout, {
        method: 'POST',
        withCredentials: true,
        csrf: true,
      })
    },

    async me() {
      const result = await client.request<User>(AUTH_PATHS.me, { auth: true })
      return result.data
    },
  }
}
