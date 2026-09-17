import type { ApiClient } from './apiClient'
import type { UserListResponse } from '../types/auth'

export const USERS_PATH = '/api/v1/users'

export interface UserService {
  list(params?: { limit?: number; offset?: number }): Promise<UserListResponse>
}

export function createUserService(client: ApiClient): UserService {
  return {
    async list({ limit = 50, offset = 0 } = {}) {
      const result = await client.request<UserListResponse>(
        `${USERS_PATH}?limit=${limit}&offset=${offset}`,
        { auth: true },
      )
      return result.data
    },
  }
}
