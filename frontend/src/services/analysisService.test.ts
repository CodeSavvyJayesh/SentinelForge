import { describe, expect, it } from 'vitest'

import { createAnalysisService } from './analysisService'
import { createApiClient, type FetchLike } from './apiClient'

interface Call {
  url: string
  init: RequestInit
}

function recordingService(responses: Response[]) {
  const calls: Call[] = []
  const queue = [...responses]
  const fetchImpl: FetchLike = async (url, init) => {
    calls.push({ url, init })
    return queue.shift() ?? new Response('{}', { status: 200 })
  }
  const client = createApiClient({
    baseUrl: 'http://api.test',
    fetchImpl,
    getAccessToken: () => 'token-1',
  })
  return { service: createAnalysisService(client), calls }
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('analysisService', () => {
  it('lists findings with pagination', async () => {
    const { service, calls } = recordingService([
      json({ items: [], total: 0, by_severity: {}, by_status: {}, limit: 50, offset: 0 }),
    ])

    await service.listFindings(5)

    expect(calls[0]?.url).toBe('http://api.test/api/v1/repositories/5/findings?limit=50&offset=0')
  })

  it('sends the severity filter only when one is chosen', async () => {
    const { service, calls } = recordingService([
      json({ items: [], total: 0, by_severity: {}, by_status: {}, limit: 50, offset: 0 }),
      json({ items: [], total: 0, by_severity: {}, by_status: {}, limit: 50, offset: 0 }),
    ])

    await service.listFindings(5, { severity: 'CRITICAL' })
    await service.listFindings(5, { severity: null })

    expect(calls[0]?.url).toContain('severity=CRITICAL')
    expect(calls[1]?.url).not.toContain('severity')
  })

  it('sends the lifecycle filter under its own parameter name', async () => {
    const { service, calls } = recordingService([
      json({ items: [], total: 0, by_severity: {}, by_status: {}, limit: 50, offset: 0 }),
      json({ items: [], total: 0, by_severity: {}, by_status: {}, limit: 50, offset: 0 }),
    ])

    await service.listFindings(5, { status: 'FIXED' })
    await service.listFindings(5, { status: null })

    expect(calls[0]?.url).toContain('finding_status=FIXED')
    expect(calls[1]?.url).not.toContain('finding_status')
  })

})
