import { describe, expect, it } from 'vitest'

import { createApiClient, type FetchLike } from './apiClient'
import { createPatchService, PATCH_POLL_INTERVAL_MS } from './patchService'
import { parseDiff, type Patch } from '../types/patch'

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
  return { service: createPatchService(client), calls }
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const DIFF = [
  '--- a/src/hash.py',
  '+++ b/src/hash.py',
  '@@ -2,5 +2,5 @@',
  ' def digest(value):',
  '-    return hashlib.md5(value).hexdigest()',
  '+    return hashlib.sha256(value).hexdigest()',
  '',
].join('\n')

const PATCH: Patch = {
  id: 5,
  finding_id: 7,
  status: 'PROPOSED',
  attempts: 1,
  diff: DIFF,
  rationale: 'Replaced MD5 with SHA-256.',
  file_path: 'src/hash.py',
  first_line: 1,
  last_line: 9,
  lines_added: 1,
  lines_removed: 1,
  validated: false,
  model: 'qwen2.5-coder:7b',
  prompt_version: 1,
  explanation_id: 3,
  fences_stripped: false,
  gutters_stripped: 0,
  reindented: false,
  rejected_code: null,
  temperature: 0,
  duration_ms: 31_000,
  prompt_tokens: 1200,
  completion_tokens: 210,
  error_message: null,
  created_at: '2026-09-27T10:00:00Z',
  finished_at: '2026-09-27T10:00:31Z',
}

describe('patchService', () => {
  it('accepts the 202 that requesting a patch returns', async () => {
    // 202, not 200: queued, not generated.
    const { service, calls } = recordingService([
      json({ ...PATCH, status: 'QUEUED', diff: null }, 202),
    ])

    const result = await service.request(7)

    expect(calls[0]?.url).toBe('http://api.test/api/v1/findings/7/patch')
    expect(calls[0]?.init.method).toBe('POST')
    expect(result.status).toBe('QUEUED')
    expect(result.diff).toBeNull()
  })

  it('fetches one patch for polling', async () => {
    const { service, calls } = recordingService([json(PATCH)])

    const result = await service.get(5)

    expect(calls[0]?.url).toBe('http://api.test/api/v1/patches/5')
    expect(result.rationale).toBe('Replaced MD5 with SHA-256.')
  })

  it('reads 204 as "never requested" rather than as an error', async () => {
    const { service } = recordingService([new Response(null, { status: 204 })])

    expect(await service.latestForFinding(7)).toBeNull()
  })

  it('returns a refused attempt so the panel can show the reason', async () => {
    const { service } = recordingService([
      json({
        ...PATCH,
        status: 'FAILED',
        diff: null,
        error_message: 'The proposed change mostly deletes code.',
        rejected_code: '    return hashlib.sha256(value).hexdigest()',
      }),
    ])

    const result = await service.latestForFinding(7)

    expect(result?.status).toBe('FAILED')
    expect(result?.error_message).toContain('mostly deletes code')
    // The refusal carries what was thrown away. That check is a heuristic and
    // can be wrong about a correct fix, so the panel shows the evidence.
    expect(result?.rejected_code).toContain('sha256')
  })

  it('surfaces a refused second request with its code', async () => {
    const { service } = recordingService([
      json(
        {
          error: {
            code: 'PATCH_ALREADY_RUNNING',
            message: 'A change is already being proposed for this finding (request 5)',
          },
        },
        409,
      ),
    ])

    await expect(service.request(7)).rejects.toMatchObject({
      code: 'PATCH_ALREADY_RUNNING',
      status: 409,
    })
  })

  it('surfaces a finding that cannot be patched', async () => {
    const { service } = recordingService([
      json(
        {
          error: {
            code: 'FINDING_NOT_PATCHABLE',
            message: 'This finding is already fixed, so there is nothing to change.',
          },
        },
        409,
      ),
    ])

    await expect(service.request(7)).rejects.toMatchObject({ code: 'FINDING_NOT_PATCHABLE' })
  })

  it('polls slowly enough not to hammer a model that takes half a minute', () => {
    expect(PATCH_POLL_INTERVAL_MS).toBe(3_000)
  })
})

describe('parseDiff', () => {
  it('classifies added, removed and context lines', () => {
    const lines = parseDiff(DIFF)

    expect(lines.find((line) => line.text.includes('sha256'))?.kind).toBe('added')
    expect(lines.find((line) => line.text.includes('md5'))?.kind).toBe('removed')
    expect(lines.find((line) => line.text === ' def digest(value):')?.kind).toBe('context')
  })

  it('does not colour the file markers as changes', () => {
    // '+++' and '---' start with the same characters as changed lines. Colour
    // them and every one-line fix reads as a two-line one.
    const lines = parseDiff(DIFF)

    expect(lines[0]?.kind).toBe('meta')
    expect(lines[1]?.kind).toBe('meta')
    expect(lines[2]?.kind).toBe('meta')
    expect(lines.filter((line) => line.kind === 'added')).toHaveLength(1)
    expect(lines.filter((line) => line.kind === 'removed')).toHaveLength(1)
  })

  it('drops only the trailing blank produced by the final newline', () => {
    const lines = parseDiff('a\n\nb\n')

    expect(lines.map((line) => line.text)).toEqual(['a', '', 'b'])
  })

  it('never throws on a malformed diff', () => {
    // The renderer's job is to display, not to interpret. Anything unexpected
    // is shown as context rather than acted upon.
    expect(() => parseDiff('')).not.toThrow()
    expect(parseDiff('nonsense')[0]?.kind).toBe('context')
  })
})
