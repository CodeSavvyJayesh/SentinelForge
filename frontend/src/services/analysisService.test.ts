import { describe, expect, it } from 'vitest'

import { ANALYSIS_TIMEOUT_MS, createAnalysisService } from './analysisService'
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

const SUMMARY = {
  repository_id: 5,
  findings: 7,
  by_severity: { CRITICAL: 2, HIGH: 3, MEDIUM: 2 },
  files_scanned: 12,
  files_skipped: 1,
  unparsable_files: 0,
  truncated: false,
  duration_ms: 430,
  analyzed_at: '2026-01-01T00:00:00Z',
}

describe('analysisService', () => {
  it('posts to the analyse endpoint', async () => {
    const { service, calls } = recordingService([json(SUMMARY)])

    const summary = await service.analyze(5)

    expect(summary.findings).toBe(7)
    expect(calls[0]?.url).toBe('http://api.test/api/v1/repositories/5/analyze')
    expect(calls[0]?.init.method).toBe('POST')
  })

  it('lists findings with pagination', async () => {
    const { service, calls } = recordingService([
      json({ items: [], total: 0, by_severity: {}, limit: 50, offset: 0 }),
    ])

    await service.listFindings(5)

    expect(calls[0]?.url).toBe('http://api.test/api/v1/repositories/5/findings?limit=50&offset=0')
  })

  it('sends the severity filter only when one is chosen', async () => {
    const { service, calls } = recordingService([
      json({ items: [], total: 0, by_severity: {}, limit: 50, offset: 0 }),
      json({ items: [], total: 0, by_severity: {}, limit: 50, offset: 0 }),
    ])

    await service.listFindings(5, { severity: 'CRITICAL' })
    await service.listFindings(5, { severity: null })

    expect(calls[0]?.url).toContain('severity=CRITICAL')
    expect(calls[1]?.url).not.toContain('severity')
  })

  it('surfaces a refused analysis with its code', async () => {
    const { service } = recordingService([
      json(
        {
          error: {
            code: 'REPOSITORY_NOT_ANALYSABLE',
            message: 'This repository has no ingested code to analyse.',
            details: null,
            request_id: 'abc',
          },
        },
        409,
      ),
    ])

    await expect(service.analyze(5)).rejects.toMatchObject({
      code: 'REPOSITORY_NOT_ANALYSABLE',
      status: 409,
    })
  })

  it('allows an analysis far longer than an ordinary request', () => {
    expect(ANALYSIS_TIMEOUT_MS > 60_000).toBe(true)
  })
})
