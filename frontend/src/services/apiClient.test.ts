import { describe, expect, it } from 'vitest'

import { ApiError, createApiClient, type FetchLike } from './apiClient'

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  })
}

function clientWith(fetchImpl: FetchLike, timeoutMs = 1_000) {
  return createApiClient({ baseUrl: 'http://api.test', fetchImpl, defaultTimeoutMs: timeoutMs })
}

describe('createApiClient', () => {
  it('returns parsed JSON, status and request id on success', async () => {
    let calledUrl = ''
    const client = clientWith(async (url) => {
      calledUrl = url
      return jsonResponse({ ok: true }, 200, { 'X-Request-ID': 'req-1' })
    })

    const result = await client.request<{ ok: boolean }>('api/v1/thing')

    expect(calledUrl).toBe('http://api.test/api/v1/thing')
    expect(result).toEqual({ data: { ok: true }, status: 200, requestId: 'req-1' })
  })

  it('returns the body for explicitly accepted non-2xx statuses', async () => {
    const client = clientWith(async () => jsonResponse({ status: 'unhealthy' }, 503))
    const result = await client.request('/health', { acceptStatuses: [503] })
    expect(result.status).toBe(503)
    expect(result.data).toEqual({ status: 'unhealthy' })
  })

  it('maps the backend error envelope to ApiError', async () => {
    const client = clientWith(async () =>
      jsonResponse(
        { error: { code: 'NOT_FOUND', message: 'Not Found', details: null, request_id: 'req-9' } },
        404,
      ),
    )
    await expect(client.request('/missing')).rejects.toMatchObject({
      name: 'ApiError',
      status: 404,
      code: 'NOT_FOUND',
      message: 'Not Found',
      requestId: 'req-9',
    })
  })

  it('reports non-envelope HTTP failures as HTTP_ERROR', async () => {
    const client = clientWith(async () => new Response('', { status: 502 }))
    await expect(client.request('/x')).rejects.toMatchObject({ status: 502, code: 'HTTP_ERROR' })
  })

  it('reports invalid JSON as INVALID_RESPONSE', async () => {
    const client = clientWith(async () => new Response('<html>', { status: 200 }))
    await expect(client.request('/x')).rejects.toMatchObject({ code: 'INVALID_RESPONSE' })
  })

  it('reports connection failures as NETWORK_ERROR', async () => {
    const client = clientWith(async () => {
      throw new TypeError('Failed to fetch')
    })
    await expect(client.request('/x')).rejects.toMatchObject({ status: 0, code: 'NETWORK_ERROR' })
  })

  it('aborts slow requests with TIMEOUT', async () => {
    const neverResolves: FetchLike = (_url, init) =>
      new Promise((_resolve, reject) => {
        init.signal?.addEventListener('abort', () => reject(new Error('aborted')))
      })
    await expect(clientWith(neverResolves, 20).request('/slow')).rejects.toMatchObject({
      code: 'TIMEOUT',
    })
  })

  it('rethrows caller aborts instead of converting them to ApiError', async () => {
    const controller = new AbortController()
    const fetchImpl: FetchLike = (_url, init) =>
      new Promise((_resolve, reject) => {
        init.signal?.addEventListener('abort', () => reject(new Error('caller aborted')))
      })
    const pending = clientWith(fetchImpl).request('/x', { signal: controller.signal })
    controller.abort()
    await expect(pending).rejects.toMatchObject({ message: 'caller aborted' })
  })

  it('fails with NOT_CONFIGURED when no base URL is set', async () => {
    const client = createApiClient({ baseUrl: null, fetchImpl: async () => jsonResponse({}) })
    const error = await client.request('/x').catch((caught: unknown) => caught)
    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).code).toBe('NOT_CONFIGURED')
  })
})
