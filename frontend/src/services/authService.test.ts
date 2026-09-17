import { describe, expect, it } from 'vitest'

import { createApiClient, type FetchLike } from './apiClient'
import { AUTH_PATHS, createAuthService } from './authService'
import { tokenStore } from './tokenStore'

interface Call {
  url: string
  init: RequestInit
}

function recordingClient(responses: Response[], options: Record<string, unknown> = {}) {
  const calls: Call[] = []
  const queue = [...responses]
  const fetchImpl: FetchLike = async (url, init) => {
    calls.push({ url, init })
    return queue.shift() ?? new Response('{}', { status: 200 })
  }
  const client = createApiClient({ baseUrl: 'http://api.test', fetchImpl, ...options })
  return { client, calls }
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const SESSION = {
  access_token: 'token-1',
  token_type: 'bearer',
  expires_in: 900,
  user: { id: 1, email: 'a@b.c', username: 'dev', role: 'USER', is_active: true, created_at: '' },
}

describe('authService', () => {
  it('sends cookies on login so the refresh cookie is stored', async () => {
    const { client, calls } = recordingClient([json(SESSION)])
    const session = await createAuthService(client).login({ identifier: 'dev', password: 'x' })

    expect(session.access_token).toBe('token-1')
    expect(calls[0]?.url).toBe(`http://api.test${AUTH_PATHS.login}`)
    expect(calls[0]?.init.credentials).toBe('include')
  })

  it('sends the CSRF header on refresh and logout', async () => {
    const noContent = new Response(null, { status: 204 })
    const { client, calls } = recordingClient([json(SESSION), noContent], {
      readCsrfToken: () => 'csrf-value',
    })
    const service = createAuthService(client)
    await service.refresh()
    await service.logout()

    for (const call of calls) {
      const headers = call.init.headers as Record<string, string>
      expect(headers['X-CSRF-Token']).toBe('csrf-value')
      expect(call.init.credentials).toBe('include')
    }
  })

  it('attaches the in-memory access token to authenticated calls', async () => {
    tokenStore.set('secret-token')
    const { client, calls } = recordingClient([json(SESSION.user)], {
      getAccessToken: () => tokenStore.get(),
    })
    await createAuthService(client).me()
    const headers = calls[0]?.init.headers as Record<string, string>

    expect(headers.Authorization).toBe('Bearer secret-token')
    tokenStore.clear()
  })

  it('refreshes once and replays the request when the token has expired', async () => {
    let refreshed = false
    const { client, calls } = recordingClient(
      [json({ error: { code: 'UNAUTHORIZED', message: 'expired' } }, 401), json(SESSION.user)],
      {
        getAccessToken: () => 'stale-token',
        onUnauthorized: async () => {
          refreshed = true
          return true
        },
      },
    )

    const user = await createAuthService(client).me()

    expect(refreshed).toBe(true)
    expect(calls).toHaveLength(2)
    expect(user.username).toBe('dev')
  })

  it('gives up after one failed refresh instead of looping', async () => {
    const { client, calls } = recordingClient(
      [
        json({ error: { code: 'UNAUTHORIZED', message: 'expired' } }, 401),
        json({ error: { code: 'UNAUTHORIZED', message: 'expired' } }, 401),
      ],
      { getAccessToken: () => 'stale', onUnauthorized: async () => true },
    )

    await expect(createAuthService(client).me()).rejects.toMatchObject({ status: 401 })
    expect(calls).toHaveLength(2)
  })

  it('propagates rate-limit errors with their code', async () => {
    const { client } = recordingClient([
      json({ error: { code: 'RATE_LIMITED', message: 'Too many attempts' } }, 429),
    ])
    await expect(
      createAuthService(client).login({ identifier: 'dev', password: 'x' }),
    ).rejects.toMatchObject({ status: 429, code: 'RATE_LIMITED' })
  })
})
