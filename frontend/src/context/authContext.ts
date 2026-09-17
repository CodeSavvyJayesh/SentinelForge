import { createContext } from 'react'

import type { ApiError } from '../services/apiClient'
import type { LoginInput, RegisterInput, User } from '../types/auth'

export type AuthStatus = 'loading' | 'authenticated' | 'anonymous'

export interface AuthContextValue {
  status: AuthStatus
  user: User | null
  /** Set when the last restore attempt failed for a reason worth showing. */
  error: ApiError | null
  login(input: LoginInput): Promise<void>
  register(input: RegisterInput): Promise<User>
  logout(): Promise<void>
}

export const AuthContext = createContext<AuthContextValue | null>(null)
