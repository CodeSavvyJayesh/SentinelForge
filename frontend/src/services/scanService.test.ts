import { describe, expect, it } from 'vitest'

import { createApiClient, type FetchLike } from './apiClient'
import { createScanService, SCAN_POLL_INTERVAL_MS } from './scanService'

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
  return { service: createScanService(client), calls }
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const QUEUED_SCAN = {
  id: 9,
  repository_id: 5,
  status: 'QUEUED',
  attempts: 0,
  started_at: null,
  finished_at: null,
  duration_ms: null,
  files_scanned: 0,
  files_skipped: 0,
  unparsable_files: 0,
  total_findings: 0,
  new_findings: 0,
  fixed_findings: 0,
  truncated: false,
  error_message: null,
  created_at: '2026-01-01T00:00:00Z',
}

describe('scanService', () => {
  it('accepts the 202 that queueing returns', async () => {
    // 202 is not a 2xx the client treats as ordinary success by default, so
    // this test exists to stop a future refactor turning "queued" into an error.
    const { service, calls } = recordingService([json(QUEUED_SCAN, 202)])

    const scan = await service.queue(5)

    expect(scan.status).toBe('QUEUED')
    expect(calls[0]?.url).toBe('http://api.test/api/v1/repositories/5/scans')
    expect(calls[0]?.init.method).toBe('POST')
  })

  it('fetches one scan for polling', async () => {
    const { service, calls } = recordingService([json({ ...QUEUED_SCAN, status: 'RUNNING' })])

    const scan = await service.get(9)

    expect(scan.status).toBe('RUNNING')
    expect(calls[0]?.url).toBe('http://api.test/api/v1/scans/9')
  })

  it('lists the history newest first, bounded', async () => {
    const { service, calls } = recordingService([
      json({ items: [QUEUED_SCAN], total: 1, limit: 10, offset: 0 }),
    ])

    const page = await service.listForRepository(5)

    expect(page.total).toBe(1)
    expect(calls[0]?.url).toBe('http://api.test/api/v1/repositories/5/scans?limit=10&offset=0')
  })

  it('surfaces a refused scan with its code', async () => {
    const { service } = recordingService([
      json(
        {
          error: {
            code: 'SCAN_ALREADY_RUNNING',
            message: 'A scan of this repository is already in progress (scan 4)',
            details: null,
            request_id: 'abc',
          },
        },
        409,
      ),
    ])

    await expect(service.queue(5)).rejects.toMatchObject({
      code: 'SCAN_ALREADY_RUNNING',
      status: 409,
    })
  })

  it('polls often enough to feel live, rarely enough not to hammer the API', () => {
    expect(SCAN_POLL_INTERVAL_MS >= 500 && SCAN_POLL_INTERVAL_MS <= 5000).toBe(true)
  })
})
