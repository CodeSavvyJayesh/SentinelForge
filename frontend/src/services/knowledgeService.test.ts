import { describe, expect, it } from 'vitest'

import { createApiClient, type FetchLike } from './apiClient'
import { createKnowledgeService } from './knowledgeService'
import type { FindingKnowledgeResponse, KnowledgeStatus } from '../types/knowledge'

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
  return { service: createKnowledgeService(client), calls }
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const KNOWLEDGE: FindingKnowledgeResponse = {
  finding_id: 7,
  rule_id: 'JV003',
  cwe_id: 'CWE-327',
  owasp_category: 'A02:2021 Cryptographic Failures',
  query: 'Weak hash algorithm (MD5 or SHA-1) CWE-327 in Java',
  passages: [
    {
      id: 1,
      source: 'SENTINELFORGE',
      external_id: 'JV003',
      document_title: 'JV003: MD5 or SHA-1 used as a hash (Java)',
      section: 'Fix',
      text: 'Change the algorithm string to "SHA-256".',
      url: null,
      source_version: null,
      score: 0.81,
      matched_by: 'rule',
    },
  ],
}

const STATUS: KnowledgeStatus = {
  built: true,
  documents: 980,
  chunks: 3100,
  embedded_chunks: 3100,
  by_source: { CWE: 938, OWASP: 10, SENTINELFORGE: 32 },
  embedding_models: ['BAAI/bge-small-en-v1.5'],
  source_versions: { CWE: '4.99', OWASP: '2021' },
  built_at: '2026-09-26T10:00:00Z',
}

describe('knowledgeService', () => {
  it('asks for one finding’s reference material, with the access token', async () => {
    const { service, calls } = recordingService([json(KNOWLEDGE)])

    const result = await service.forFinding(7)

    expect(calls[0]?.url).toBe('http://api.test/api/v1/findings/7/knowledge')
    expect(new Headers(calls[0]?.init.headers).get('Authorization')).toBe('Bearer token-1')
    expect(result.passages[0]?.matched_by).toBe('rule')
    expect(result.query).toContain('CWE-327')
  })

  it('reads the knowledge base status', async () => {
    const { service, calls } = recordingService([json(STATUS)])

    const result = await service.status()

    expect(calls[0]?.url).toBe('http://api.test/api/v1/knowledge/status')
    expect(result.built).toBe(true)
    expect(result.embedding_models).toEqual(['BAAI/bge-small-en-v1.5'])
  })

  it('surfaces an unbuilt knowledge base as its own error code', async () => {
    // The UI branches on this: "nobody indexed anything here" is a fact about
    // the installation, not a verdict on the user's code.
    const { service } = recordingService([
      json(
        {
          error: {
            code: 'KNOWLEDGE_BASE_NOT_BUILT',
            message: 'The security knowledge base has not been built yet.',
          },
        },
        503,
      ),
    ])

    await expect(service.forFinding(7)).rejects.toMatchObject({
      code: 'KNOWLEDGE_BASE_NOT_BUILT',
      status: 503,
    })
  })

  it('surfaces a missing finding as a 404 rather than an empty result', async () => {
    const { service } = recordingService([
      json({ error: { code: 'FINDING_NOT_FOUND', message: 'Finding not found' } }, 404),
    ])

    await expect(service.forFinding(999)).rejects.toMatchObject({
      code: 'FINDING_NOT_FOUND',
      status: 404,
    })
  })
})
