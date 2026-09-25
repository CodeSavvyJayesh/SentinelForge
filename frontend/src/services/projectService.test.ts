import { describe, expect, it } from 'vitest'

import { createApiClient, type FetchLike } from './apiClient'
import { PROJECTS_PATH, createProjectService } from './projectService'

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
  return { service: createProjectService(client), calls }
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const PROJECT = {
  id: 3,
  owner_id: 1,
  name: 'SecureBank',
  description: null,
  repository_url: null,
  default_branch: 'main',
  language: null,
  created_at: '2026-09-25T10:00:00Z',
  updated_at: '2026-09-25T10:00:00Z',
}

describe('projectService', () => {
  it('sends the access token on every call', async () => {
    const { service, calls } = recordingService([json({ items: [], total: 0, limit: 20, offset: 0 })])
    await service.list()
    const headers = calls[0]?.init.headers as Record<string, string>
    expect(headers.Authorization).toBe('Bearer token-1')
  })

  it('builds pagination and search parameters', async () => {
    const { service, calls } = recordingService([json({ items: [], total: 0, limit: 5, offset: 10 })])
    await service.list({ search: ' api ', limit: 5, offset: 10 })
    expect(calls[0]?.url).toBe(`http://api.test${PROJECTS_PATH}?limit=5&offset=10&search=api`)
  })

  it('omits an empty search term', async () => {
    const { service, calls } = recordingService([json({ items: [], total: 0, limit: 20, offset: 0 })])
    await service.list({ search: '   ' })
    expect(calls[0]?.url).not.toContain('search')
  })

  it('creates a project with POST and returns it', async () => {
    const { service, calls } = recordingService([json(PROJECT, 201)])
    const project = await service.create({ name: 'SecureBank' })
    expect(calls[0]?.init.method).toBe('POST')
    expect(project.name).toBe('SecureBank')
  })

  it('updates with PATCH', async () => {
    const { service, calls } = recordingService([json({ ...PROJECT, name: 'Renamed' })])
    const project = await service.update(3, { name: 'Renamed' })
    expect(calls[0]?.init.method).toBe('PATCH')
    expect(calls[0]?.url).toBe(`http://api.test${PROJECTS_PATH}/3`)
    expect(project.name).toBe('Renamed')
  })

  it('deletes with DELETE and accepts an empty body', async () => {
    const { service, calls } = recordingService([new Response(null, { status: 204 })])
    await service.remove(3)
    expect(calls[0]?.init.method).toBe('DELETE')
  })

  it("surfaces 404 for someone else's project without special-casing it", async () => {
    const { service } = recordingService([
      json({ error: { code: 'PROJECT_NOT_FOUND', message: 'Project not found' } }, 404),
    ])
    await expect(service.get(99)).rejects.toMatchObject({
      status: 404,
      code: 'PROJECT_NOT_FOUND',
    })
  })

  it('surfaces a duplicate-name conflict', async () => {
    const { service } = recordingService([
      json({ error: { code: 'PROJECT_NAME_TAKEN', message: 'You already have a project…' } }, 409),
    ])
    await expect(service.create({ name: 'SecureBank' })).rejects.toMatchObject({
      status: 409,
      code: 'PROJECT_NAME_TAKEN',
    })
  })
})
