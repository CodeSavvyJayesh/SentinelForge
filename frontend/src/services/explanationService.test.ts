import { describe, expect, it } from 'vitest'

import { createApiClient, type FetchLike } from './apiClient'
import { createExplanationService, EXPLANATION_POLL_INTERVAL_MS } from './explanationService'
import type { Explanation } from '../types/explanation'

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
  return { service: createExplanationService(client), calls }
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const EXPLANATION: Explanation = {
  id: 3,
  finding_id: 7,
  status: 'COMPLETED',
  attempts: 1,
  summary: 'MD5 is used to hash a password.',
  impact: 'An attacker with the database recovers passwords quickly.',
  remediation: 'Use scrypt or Argon2.',
  model: 'qwen2.5-coder:7b',
  prompt_version: 1,
  citations: [
    {
      number: 1,
      chunk_id: 42,
      source: 'CWE',
      external_id: 'CWE-327',
      document_title: 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm',
      section: 'Mitigations',
      url: 'https://cwe.mitre.org/data/definitions/327.html',
    },
  ],
  grounded: true,
  dropped_citations: 0,
  links_removed: 0,
  duration_ms: 24_000,
  prompt_tokens: 900,
  completion_tokens: 180,
  error_message: null,
  created_at: '2026-09-26T10:00:00Z',
  finished_at: '2026-09-26T10:00:24Z',
}

describe('explanationService', () => {
  it('accepts the 202 that requesting an explanation returns', async () => {
    // 202, not 200: queued, not generated.
    const { service, calls } = recordingService([
      json({ ...EXPLANATION, status: 'QUEUED', summary: null }, 202),
    ])

    const result = await service.request(7)

    expect(calls[0]?.url).toBe('http://api.test/api/v1/findings/7/explanation')
    expect(calls[0]?.init.method).toBe('POST')
    expect(result.status).toBe('QUEUED')
  })

  it('fetches one explanation for polling', async () => {
    const { service, calls } = recordingService([json(EXPLANATION)])

    const result = await service.get(3)

    expect(calls[0]?.url).toBe('http://api.test/api/v1/explanations/3')
    expect(result.citations[0]?.external_id).toBe('CWE-327')
  })

  it('reads 204 as "never requested" rather than as an error', async () => {
    // "Nobody has asked" and "asked and got nothing" are different states, and
    // the panel says something different for each.
    const { service } = recordingService([new Response(null, { status: 204 })])

    expect(await service.latestForFinding(7)).toBeNull()
  })

  it('returns the latest explanation when there is one', async () => {
    const { service } = recordingService([json({ ...EXPLANATION, status: 'FAILED' })])

    const result = await service.latestForFinding(7)

    // A failed attempt is still returned: the panel shows the reason instead
    // of an empty space that looks like a missing feature.
    expect(result?.status).toBe('FAILED')
  })

  it('surfaces a refused second request with its code', async () => {
    const { service } = recordingService([
      json(
        {
          error: {
            code: 'EXPLANATION_ALREADY_RUNNING',
            message: 'This finding is already being explained (request 3)',
          },
        },
        409,
      ),
    ])

    await expect(service.request(7)).rejects.toMatchObject({
      code: 'EXPLANATION_ALREADY_RUNNING',
      status: 409,
    })
  })

  it('polls slowly enough not to hammer a model that takes half a minute', () => {
    expect(EXPLANATION_POLL_INTERVAL_MS).toBe(3_000)
  })
})
