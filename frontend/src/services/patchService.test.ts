import { describe, expect, it } from 'vitest'

import { createApiClient, type FetchLike } from './apiClient'
import {
  createPatchService,
  PATCH_POLL_INTERVAL_MS,
  VALIDATION_POLL_INTERVAL_MS,
} from './patchService'
import {
  isSettling,
  parseDiff,
  validationState,
  type Patch,
  type PatchValidation,
} from '../types/patch'

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
  validation: null,
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

const VALIDATION: PatchValidation = {
  id: 9,
  status: 'PASSED',
  attempts: 1,
  checks: [
    { key: 'target_resolved', outcome: 'passed', detail: 'PY007 is no longer detected.' },
    { key: 'no_new_findings', outcome: 'passed', detail: 'Nothing new.' },
    { key: 'not_a_deletion', outcome: 'passed', detail: 'The change replaces code with code.' },
    { key: 'still_parses', outcome: 'skipped', detail: 'Only Python is parsed here.' },
  ],
  findings_before: 2,
  findings_after: 1,
  also_resolved: 0,
  new_findings: [],
  duration_ms: 7,
  error_message: null,
  created_at: '2026-10-02T10:00:00Z',
  finished_at: '2026-10-02T10:00:00Z',
}

function withValidation(status: PatchValidation['status'], validated: boolean): Patch {
  return { ...PATCH, validated, validation: { ...VALIDATION, status } }
}

describe('patch validation', () => {
  it('queues a re-scan with a POST and accepts the 202', async () => {
    const { service, calls } = recordingService([
      json(withValidation('QUEUED', false), 202),
    ])

    const result = await service.requestValidation(5)

    expect(calls[0]?.url).toBe('http://api.test/api/v1/patches/5/validation')
    expect(calls[0]?.init.method).toBe('POST')
    expect(result.validation?.status).toBe('QUEUED')
    // Queued is not validated.
    expect(result.validated).toBe(false)
  })

  it('surfaces a refusal to check a patch that was never proposed', async () => {
    const { service } = recordingService([
      json({ error: { code: 'PATCH_NOT_VALIDATABLE', message: 'Only a proposed change…' } }, 409),
    ])

    await expect(service.requestValidation(5)).rejects.toMatchObject({
      code: 'PATCH_NOT_VALIDATABLE',
      status: 409,
    })
  })

  it('polls a re-scan faster than a generation', () => {
    // The check takes milliseconds; the model takes a minute.
    expect(VALIDATION_POLL_INTERVAL_MS).toBe(1_000)
    expect(VALIDATION_POLL_INTERVAL_MS < PATCH_POLL_INTERVAL_MS).toBe(true)
  })
})

describe('validationState', () => {
  it('is unchecked when no validation has ever been made', () => {
    expect(validationState(PATCH)).toBe('unchecked')
  })

  it('is checking while a re-scan is queued or running', () => {
    expect(validationState(withValidation('QUEUED', false))).toBe('checking')
    expect(validationState(withValidation('RUNNING', false))).toBe('checking')
  })

  it('is validated only when the check passed and the server agrees', () => {
    expect(validationState(withValidation('PASSED', true))).toBe('validated')
  })

  it('does not call a passed check validated if the server did not', () => {
    // The two should never disagree. If they do, the cautious reading wins:
    // the panel must not print a verdict the server did not give.
    expect(validationState(withValidation('PASSED', false))).toBe('undetermined')
  })

  it('is rejected when the re-scan contradicted the change', () => {
    expect(validationState(withValidation('REJECTED', false))).toBe('rejected')
  })

  it('keeps "could not be checked" apart from "rejected"', () => {
    // A stale workspace says nothing about the patch. Showing it as a
    // rejection would blame the change for something it did not do.
    expect(validationState(withValidation('FAILED', false))).toBe('undetermined')
  })
})

describe('isSettling', () => {
  it('keeps polling while the model is still writing', () => {
    expect(isSettling({ ...PATCH, status: 'RUNNING', diff: null })).toBe(true)
  })

  it('keeps polling while the re-scan is still running', () => {
    expect(isSettling(withValidation('RUNNING', false))).toBe(true)
  })

  it('stops once there is a verdict, whichever it is', () => {
    expect(isSettling(withValidation('PASSED', true))).toBe(false)
    expect(isSettling(withValidation('REJECTED', false))).toBe(false)
    expect(isSettling(withValidation('FAILED', false))).toBe(false)
  })

  it('stops for a proposal that was never checked', () => {
    // Nothing is in flight; polling forever would hammer the API for nothing.
    expect(isSettling(PATCH)).toBe(false)
  })
})
