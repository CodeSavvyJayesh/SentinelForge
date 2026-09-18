import { useCallback, useEffect, useState } from 'react'

import { ApiError, toApiError } from '../services/apiClient'
import { healthService } from '../services/api'
import type { HealthService } from '../services/healthService'
import type { ApiResult } from '../types/api'
import type { HealthResponse } from '../types/health'

export type HealthState =
  | { status: 'loading' }
  | { status: 'success'; result: ApiResult<HealthResponse> }
  | { status: 'error'; error: ApiError }

/** Loads backend health once on mount; `refresh()` re-checks on demand. */
export function useHealth(service: HealthService = healthService) {
  const [state, setState] = useState<HealthState>({ status: 'loading' })
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    service
      .getHealth(controller.signal)
      .then((result) => setState({ status: 'success', result }))
      .catch((error: unknown) => {
        if (controller.signal.aborted) return
        setState({ status: 'error', error: toApiError(error) })
      })
    return () => controller.abort()
  }, [service, attempt])

  const refresh = useCallback(() => {
    setState({ status: 'loading' })
    setAttempt((value) => value + 1)
  }, [])

  return { state, refresh }
}
