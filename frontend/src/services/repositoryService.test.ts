import { describe, expect, it } from 'vitest'

import { createApiClient, type FetchLike } from './apiClient'
import { createRepositoryService, INGEST_TIMEOUT_MS } from './repositoryService'

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
  return { service: createRepositoryService(client), calls }
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const REPOSITORY = {
  id: 5,
  project_id: 3,
  source: 'UPLOAD',
  status: 'READY',
  origin: 'code.zip',
  branch: null,
  commit_hash: null,
  file_count: 12,
  total_bytes: 40_000,
  primary_language: 'Python',
  language_breakdown: { Python: 30_000, YAML: 10_000 },
  error_message: null,
  ingested_at: '2026-01-01T00:00:00Z',
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}

describe('repositoryService', () => {
  it('lists the repositories of one project', async () => {
    const { service, calls } = recordingService([json({ items: [REPOSITORY], total: 1 })])

    const result = await service.listForProject(3)

    expect(result.total).toBe(1)
    expect(calls[0]?.url).toBe('http://api.test/api/v1/projects/3/repositories')
    expect(calls[0]?.init.method ?? 'GET').toBe('GET')
    expect((calls[0]?.init.headers as Record<string, string>).Authorization).toBe('Bearer token-1')
  })

  it('uploads a file as multipart form data', async () => {
    const { service, calls } = recordingService([json(REPOSITORY, 201)])
    const file = new File(['zip-bytes'], 'code.zip', { type: 'application/zip' })

    await service.upload(3, file)

    const call = calls[0]
    expect(call?.url).toBe('http://api.test/api/v1/projects/3/repositories/upload')
    expect(call?.init.method).toBe('POST')
    expect(call?.init.body).toBeInstanceOf(FormData)
    expect((call?.init.body as FormData).get('file')).toBe(file)
    // The browser must set Content-Type itself, so the boundary is correct.
    expect((call?.init.headers as Record<string, string>)['Content-Type']).toBeUndefined()
  })

  it('sends a git url as json with the branch', async () => {
    const { service, calls } = recordingService([json(REPOSITORY, 201)])

    await service.connectGit(3, { repository_url: 'https://example.com/x.git', branch: 'main' })

    const call = calls[0]
    expect(call?.url).toBe('http://api.test/api/v1/projects/3/repositories/git')
    expect(JSON.parse(call?.init.body as string)).toEqual({
      repository_url: 'https://example.com/x.git',
      branch: 'main',
    })
  })

  it('sends a null branch when none is given', async () => {
    const { service, calls } = recordingService([json(REPOSITORY, 201)])

    await service.connectGit(3, { repository_url: 'https://example.com/x.git' })

    expect(JSON.parse(calls[0]?.init.body as string).branch).toBeNull()
  })

  it('deletes by repository id', async () => {
    const { service, calls } = recordingService([new Response(null, { status: 204 })])

    await service.remove(5)

    expect(calls[0]?.url).toBe('http://api.test/api/v1/repositories/5')
    expect(calls[0]?.init.method).toBe('DELETE')
  })

  it('surfaces the API error message and code', async () => {
    const { service } = recordingService([
      json(
        {
          error: {
            code: 'ARCHIVE_UNSAFE',
            message: 'The archive contains a path that escapes the target folder',
            details: null,
            request_id: 'abc',
          },
        },
        400,
      ),
    ])
    const file = new File(['x'], 'evil.zip')

    await expect(service.upload(3, file)).rejects.toMatchObject({
      code: 'ARCHIVE_UNSAFE',
      status: 400,
      requestId: 'abc',
    })
  })

  it('allows ingestion far longer than an ordinary request', () => {
    // Reading and indexing a large repository takes more than the 10s default.
    expect(INGEST_TIMEOUT_MS > 60_000).toBe(true)
  })
})
