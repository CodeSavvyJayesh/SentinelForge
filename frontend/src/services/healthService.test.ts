import { describe, expect, it } from 'vitest'

import type { ApiClient } from './apiClient'
import { createHealthService, isHealthResponse } from './healthService'

const validReport = {
  status: 'unhealthy',
  version: '0.1.0',
  checked_at: '2026-09-17T10:00:00Z',
  checks: { database: { status: 'down', latency_ms: null, message: 'Database connection failed' } },
}

function stubClient(data: unknown, status = 200): ApiClient {
  return {
    request: async <T,>() => ({ data: data as T, status, requestId: 'req-1' }),
  }
}

describe('healthService', () => {
  it('accepts a valid report (including 503 unhealthy)', async () => {
    const result = await createHealthService(stubClient(validReport, 503)).getHealth()
    expect(result.data.status).toBe('unhealthy')
    expect(result.status).toBe(503)
  })

  it('rejects an unexpected response shape', async () => {
    const service = createHealthService(stubClient({ status: 'healthy', database: 'connected' }))
    await expect(service.getHealth()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
  })

  it('validates latency and status types', () => {
    expect(isHealthResponse(validReport)).toBe(true)
    expect(
      isHealthResponse({
        ...validReport,
        checks: { database: { status: 'up', latency_ms: '12' } },
      }),
    ).toBe(false)
  })
})
