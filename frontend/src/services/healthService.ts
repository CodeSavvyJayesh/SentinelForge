import type { ApiResult } from '../types/api'
import type { DependencyCheck, HealthResponse } from '../types/health'
import { ApiError, ClientErrorCode, type ApiClient } from './apiClient'

export const HEALTH_PATH = '/api/v1/health'

function isDependencyCheck(value: unknown): value is DependencyCheck {
  if (typeof value !== 'object' || value === null) return false
  const check = value as Record<string, unknown>
  return (
    (check.status === 'up' || check.status === 'down') &&
    (check.latency_ms === null || typeof check.latency_ms === 'number')
  )
}

/** Runtime guard: never trust that the server returned the expected shape. */
export function isHealthResponse(value: unknown): value is HealthResponse {
  if (typeof value !== 'object' || value === null) return false
  const report = value as Record<string, unknown>
  const checks = report.checks as Record<string, unknown> | undefined
  return (
    (report.status === 'healthy' || report.status === 'unhealthy') &&
    typeof report.version === 'string' &&
    typeof report.checked_at === 'string' &&
    typeof checks === 'object' &&
    checks !== null &&
    isDependencyCheck(checks.database)
  )
}

export interface HealthService {
  getHealth(signal?: AbortSignal): Promise<ApiResult<HealthResponse>>
}

export function createHealthService(client: ApiClient): HealthService {
  return {
    async getHealth(signal) {
      // 503 still carries a full health report describing what is down.
      const result = await client.request<unknown>(HEALTH_PATH, { signal, acceptStatuses: [503] })
      if (!isHealthResponse(result.data)) {
        throw new ApiError({
          status: result.status,
          code: ClientErrorCode.INVALID_RESPONSE,
          message: 'The health endpoint returned an unexpected response',
          requestId: result.requestId,
        })
      }
      return { ...result, data: result.data }
    },
  }
}
