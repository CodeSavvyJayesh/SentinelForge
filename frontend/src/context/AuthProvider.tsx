import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'

import { authService } from '../services/api'
import { ApiError, CSRF_COOKIE_NAME, toApiError } from '../services/apiClient'
import { tokenStore } from '../services/tokenStore'
import type { LoginInput, RegisterInput, TokenResponse, User } from '../types/auth'
import { readCookie } from '../utils/cookies'
import { AuthContext, type AuthContextValue, type AuthStatus } from './authContext'

/** Refresh this many seconds before the access token actually expires. */
const REFRESH_MARGIN_SECONDS = 60
const MIN_REFRESH_DELAY_MS = 5_000

export function AuthProvider({ children }: { children: ReactNode }) {
  // Without the CSRF cookie there is no session to restore, so start as
  // anonymous instead of flashing a loading state and calling setState in an
  // effect (which would cause a cascading render).
  const [status, setStatus] = useState<AuthStatus>(() =>
    readCookie(CSRF_COOKIE_NAME) ? 'loading' : 'anonymous',
  )
  const [user, setUser] = useState<User | null>(null)
  const [error, setError] = useState<ApiError | null>(null)
  const refreshTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  // The scheduled refresh has to call back into applySession, which schedules
  // the next one. A ref breaks that cycle without capturing a stale closure.
  const applySessionRef = useRef<(session: TokenResponse) => void>(() => {})

  const clearTimer = useCallback(() => {
    if (refreshTimer.current) {
      clearTimeout(refreshTimer.current)
      refreshTimer.current = null
    }
  }, [])

  const endSession = useCallback(() => {
    clearTimer()
    tokenStore.clear()
    setUser(null)
    setStatus('anonymous')
  }, [clearTimer])

  const applySession = useCallback(
    (session: TokenResponse) => {
      tokenStore.set(session.access_token)
      setUser(session.user)
      setStatus('authenticated')
      setError(null)
      clearTimer()
      const delay = Math.max(
        MIN_REFRESH_DELAY_MS,
        (session.expires_in - REFRESH_MARGIN_SECONDS) * 1000,
      )
      refreshTimer.current = setTimeout(() => {
        void authService
          .refresh()
          .then((next) => applySessionRef.current(next))
          .catch(() => endSession())
      }, delay)
    },
    [clearTimer, endSession],
  )

  useEffect(() => {
    applySessionRef.current = applySession
  }, [applySession])

  // On first load the access token is gone (it only lived in memory), but the
  // refresh cookie may still be valid: try to restore the session silently.
  useEffect(() => {
    if (!readCookie(CSRF_COOKIE_NAME)) return
    const controller = new AbortController()
    authService
      .refresh(controller.signal)
      .then((session) => {
        if (!controller.signal.aborted) applySession(session)
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted) return
        const apiError = toApiError(caught)
        // 401/403 simply mean "not signed in"; anything else is worth showing.
        if (apiError.status !== 401 && apiError.status !== 403) setError(apiError)
        endSession()
      })
    return () => {
      controller.abort()
      clearTimer()
    }
  }, [applySession, endSession, clearTimer])

  const login = useCallback(
    async (input: LoginInput) => {
      const session = await authService.login(input)
      applySession(session)
    },
    [applySession],
  )

  const register = useCallback(async (input: RegisterInput) => authService.register(input), [])

  const logout = useCallback(async () => {
    try {
      await authService.logout()
    } finally {
      endSession()
    }
  }, [endSession])

  const value = useMemo<AuthContextValue>(
    () => ({ status, user, error, login, register, logout }),
    [status, user, error, login, register, logout],
  )

  return <AuthContext value={value}>{children}</AuthContext>
}
