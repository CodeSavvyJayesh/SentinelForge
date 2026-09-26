import { describe, expect, it } from 'vitest'

import { createApiClient, type FetchLike } from './apiClient'
import { createRiskService } from './riskService'
import type { RepositoryRisk, RiskHistory } from '../types/risk'

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
  return { service: createRiskService(client), calls }
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const RISK: RepositoryRisk = {
  repository_id: 4,
  score: 52.4,
  grade: 'D',
  policy_version: 1,
  finding_count: 18,
  counts_by_severity: { CRITICAL: 3, HIGH: 10, MEDIUM: 5 },
  top: [
    {
      finding_id: 33,
      score: 40,
      base: 40,
      factors: [
        { name: 'confidence', value: 1, reason: 'HIGH confidence that this is a real match' },
        { name: 'application path', value: 1, reason: 'in application code' },
        { name: 'age', value: 1, reason: 'open for 0 days' },
      ],
      explanation: '40 base × 1 confidence × 1 application path × 1 age = 40',
      title: 'SQL query built by string formatting',
      severity: 'CRITICAL',
      file_path: 'app/main.py',
      line_start: 24,
    },
  ],
}

const HISTORY: RiskHistory = {
  repository_id: 4,
  points: [
    {
      scan_id: 1,
      score: 60,
      grade: 'D',
      policy_version: 1,
      total_findings: 20,
      finished_at: '2026-09-25T10:00:00Z',
    },
    {
      scan_id: 2,
      score: 52.4,
      grade: 'D',
      policy_version: 1,
      total_findings: 18,
      finished_at: '2026-09-26T10:00:00Z',
    },
  ],
}

describe('riskService', () => {
  it('asks for the repository score with its working', async () => {
    const { service, calls } = recordingService([json(RISK)])

    const result = await service.forRepository(4)

    expect(calls[0]?.url).toBe('http://api.test/api/v1/repositories/4/risk?top=5')
    expect(new Headers(calls[0]?.init.headers).get('Authorization')).toBe('Bearer token-1')
    expect(result.grade).toBe('D')
    // The arithmetic travels with the score — that is the feature.
    expect(result.top[0]?.explanation).toContain('40 base')
    expect(result.top[0]?.factors).toHaveLength(3)
  })

  it('bounds how many findings the working shows', async () => {
    const { service, calls } = recordingService([json(RISK)])

    await service.forRepository(4, 3)

    expect(calls[0]?.url).toContain('top=3')
  })

  it('reads history oldest first, for a chart that goes left to right', async () => {
    const { service, calls } = recordingService([json(HISTORY)])

    const result = await service.history(4)

    expect(calls[0]?.url).toBe('http://api.test/api/v1/repositories/4/risk/history?limit=20')
    expect(result.points.map((point) => point.score)).toEqual([60, 52.4])
  })

  it('carries the policy version so two scoring schemes are distinguishable', async () => {
    const { service } = recordingService([json(HISTORY)])

    const result = await service.history(4)

    expect(result.points[0]?.policy_version).toBe(1)
  })

  it('surfaces a missing repository as a 404 rather than a zero score', async () => {
    const { service } = recordingService([
      json({ error: { code: 'REPOSITORY_NOT_FOUND', message: 'Repository not found' } }, 404),
    ])

    await expect(service.forRepository(999)).rejects.toMatchObject({
      code: 'REPOSITORY_NOT_FOUND',
      status: 404,
    })
  })
})
