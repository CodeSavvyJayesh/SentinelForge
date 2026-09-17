/** Mirrors backend/app/schemas/user.py and auth.py */
export type UserRole = 'USER' | 'ADMIN'

export interface User {
  id: number
  email: string
  username: string
  role: UserRole
  is_active: boolean
  created_at: string
}

export interface TokenResponse {
  access_token: string
  token_type: string
  /** Access token lifetime in seconds. */
  expires_in: number
  user: User
}

export interface UserListResponse {
  items: User[]
  total: number
  limit: number
  offset: number
}

export interface RegisterInput {
  email: string
  username: string
  password: string
}

export interface LoginInput {
  identifier: string
  password: string
}
