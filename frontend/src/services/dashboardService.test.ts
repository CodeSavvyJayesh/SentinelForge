import { describe, expect, it } from 'vitest'

import { createApiClient, type FetchLike } from './apiClient'
import { createDashboardService } from './dashboardService'
import type { Dashboard, DashboardFixes } from '../types/dashboard'
import {
  barPercent,
  fixRows,
  passRate,
  repositoryLabel,
  severityRows,
  weaknessRows,
} from '../types/dashboard'

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
  return { service: createDashboardService(client), calls }
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const FIXES: DashboardFixes = {
  requested: 10,
  generating: 1,
  refused: 2,
  proposed: 7,
  passed: 3,
  rejected: 1,
  not_judged: 1,
  checking: 1,
  unchecked: 1,
  labelled: 4,
}

const NO_FIXES: DashboardFixes = {
  requested: 0,
  generating: 0,
  refused: 0,
  proposed: 0,
  passed: 0,
  rejected: 0,
  not_judged: 0,
  checking: 0,
  unchecked: 0,
  labelled: 0,
}

const DASHBOARD: Dashboard = {
  generated_at: '2026-10-04T09:00:00Z',
  policy_version: 1,
  totals: {
    projects: 2,
    repositories: 3,
    repositories_scanned: 2,
    scans_completed: 5,
    open_findings: 12,
    fixed_findings: 4,
  },
  open_by_severity: { CRITICAL: 2, HIGH: 8, MEDIUM: 2, LOW: 0, INFO: 0 },
  repositories: [
    {
      repository_id: 7,
      project_id: 1,
      project_name: 'payments',
      origin: 'payments.zip',
      primary_language: 'Python',
      score: 61.2,
      grade: 'D',
      open_findings: 10,
      fixed_findings: 4,
      counts_by_severity: { CRITICAL: 2, HIGH: 6, MEDIUM: 2, LOW: 0, INFO: 0 },
      last_scan_at: '2026-10-03T10:00:00Z',
      trend: [
        { scan_id: 1, score: 70, grade: 'D', total_findings: 14, finished_at: '2026-10-01T10:00:00Z' },
        { scan_id: 2, score: 61.2, grade: 'D', total_findings: 10, finished_at: '2026-10-03T10:00:00Z' },
      ],
    },
    {
      repository_id: 9,
      project_id: 2,
      project_name: 'website',
      origin: 'https://github.com/example/website.git',
      primary_language: null,
      score: null,
      grade: null,
      open_findings: 0,
      fixed_findings: 0,
      counts_by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      last_scan_at: null,
      trend: [],
    },
  ],
  top_findings: [],
  weaknesses: [
    {
      cwe_id: 'CWE-327',
      owasp_category: 'A02:2021 Cryptographic Failures',
      title: 'Weak hash function',
      count: 8,
      worst_severity: 'HIGH',
    },
    {
      cwe_id: null,
      owasp_category: null,
      title: 'Debug mode enabled',
      count: 2,
      worst_severity: 'MEDIUM',
    },
  ],
  fixes: FIXES,
}

describe('dashboardService', () => {
  it('asks for the dashboard with no id — who is asking is the only input', async () => {
    const { service, calls } = recordingService([json(DASHBOARD)])

    const result = await service.load()

    expect(calls).toHaveLength(1)
    expect(calls[0]?.url).toBe('http://api.test/api/v1/dashboard')
    expect(new Headers(calls[0]?.init.headers).get('Authorization')).toBe('Bearer token-1')
    expect(result.totals.open_findings).toBe(12)
  })

  it('keeps an unscanned repository unscored rather than turning null into zero', async () => {
    const { service } = recordingService([json(DASHBOARD)])

    const result = await service.load()

    expect(result.repositories[1]?.score).toBeNull()
    expect(result.repositories[1]?.grade).toBeNull()
  })

  it('surfaces a failure as an error instead of an empty dashboard', async () => {
    const { service } = recordingService([
      json({ error: { code: 'NOT_AUTHENTICATED', message: 'Sign in to continue' } }, 401),
    ])

    await expect(service.load()).rejects.toMatchObject({ code: 'NOT_AUTHENTICATED', status: 401 })
  })
})

describe('barPercent', () => {
  it('scales to the largest value in the list', () => {
    expect(barPercent(8, 8)).toBe(100)
    expect(barPercent(2, 8)).toBe(25)
  })

  it('draws nothing for zero', () => {
    expect(barPercent(0, 8)).toBe(0)
    expect(barPercent(0, 0)).toBe(0)
  })

  it('never rounds a real count down to an invisible bar', () => {
    expect(barPercent(1, 400)).toBe(2)
  })

  it('never draws past the end of the track', () => {
    expect(barPercent(9, 8)).toBe(100)
  })
})

describe('severityRows', () => {
  it('lists all five severities worst first, zeros included', () => {
    const rows = severityRows(DASHBOARD.open_by_severity)

    expect(rows.map((row) => row.label)).toEqual(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])
    expect(rows.map((row) => row.value)).toEqual([2, 8, 2, 0, 0])
    expect(rows.map((row) => row.percent)).toEqual([25, 100, 25, 0, 0])
  })

  it('treats a severity the API left out as zero, not as missing', () => {
    const rows = severityRows({ HIGH: 3 })

    expect(rows.map((row) => row.value)).toEqual([0, 3, 0, 0, 0])
  })

  it('says each count in words, with its share of the total', () => {
    const rows = severityRows(DASHBOARD.open_by_severity)

    expect(rows[1]?.description).toBe('HIGH: 8 open findings, 67% of all open findings')
    expect(severityRows({ LOW: 1 })[3]?.description).toBe(
      'LOW: 1 open finding, 100% of all open findings',
    )
    expect(severityRows({})[0]?.description).toBe('CRITICAL: 0 open findings, 0% of all open findings')
  })

  it('does not round a small share to zero', () => {
    const rows = severityRows({ CRITICAL: 1, LOW: 400 })

    expect(rows[0]?.description).toContain('under 1%')
  })
})

describe('weaknessRows', () => {
  it('labels a row with its CWE and the commonest title', () => {
    const rows = weaknessRows(DASHBOARD.weaknesses)

    expect(rows[0]).toMatchObject({
      key: 'CWE-327',
      label: 'CWE-327 · Weak hash function',
      value: 8,
      percent: 100,
    })
    expect(rows[0]?.description).toBe(
      '8 open findings, worst severity HIGH, A02:2021 Cryptographic Failures',
    )
  })

  it('shows a finding with no CWE by its title alone', () => {
    const rows = weaknessRows(DASHBOARD.weaknesses)

    expect(rows[1]).toMatchObject({ key: 'unclassified', label: 'Debug mode enabled', percent: 25 })
    expect(rows[1]?.description).toBe('2 open findings, worst severity MEDIUM')
  })

  it('returns nothing for nothing', () => {
    expect(weaknessRows([])).toEqual([])
  })
})

describe('fixRows', () => {
  it('lists outcomes in the order they happen, with both verdicts first', () => {
    const rows = fixRows(FIXES)

    expect(rows.map((row) => [row.key, row.value])).toEqual([
      ['passed', 3],
      ['rejected', 1],
      ['not_judged', 1],
      ['unchecked', 1],
      ['refused', 2],
      ['in_progress', 2],
    ])
    expect(rows[0]?.percent).toBe(100)
  })

  it('accounts for every request exactly once', () => {
    const total = fixRows(FIXES).reduce((sum, row) => sum + row.value, 0)

    expect(total).toBe(FIXES.requested)
  })

  it('keeps a verdict of zero but drops other empty rows', () => {
    const rows = fixRows({ ...NO_FIXES, requested: 2, refused: 2 })

    expect(rows.map((row) => [row.key, row.value])).toEqual([
      ['passed', 0],
      ['rejected', 0],
      ['refused', 2],
    ])
  })

  it('says what each outcome means', () => {
    expect(fixRows(FIXES)[2]?.description).toBe(
      'Could not be checked: 1 of 10 requests — the stored code had changed, so the re-scan says nothing about the change',
    )
  })
})

describe('passRate', () => {
  it('is the share of judged proposals that passed', () => {
    expect(passRate(FIXES)).toBe(75)
  })

  it('is unknown, not zero, when nothing has been judged', () => {
    expect(passRate(NO_FIXES)).toBeNull()
    expect(passRate({ ...NO_FIXES, requested: 3, proposed: 3, not_judged: 3 })).toBeNull()
  })

  it('is zero when everything judged was rejected', () => {
    expect(passRate({ ...NO_FIXES, requested: 2, proposed: 2, rejected: 2, labelled: 2 })).toBe(0)
  })
})

describe('repositoryLabel', () => {
  it('leaves an uploaded archive name alone', () => {
    expect(repositoryLabel('payments.zip')).toBe('payments.zip')
  })

  it('shortens a clone URL to owner and name', () => {
    expect(repositoryLabel('https://github.com/example/website.git')).toBe('example/website')
    expect(repositoryLabel('https://github.com/example/website/')).toBe('example/website')
  })

  it('does not mistake a file name containing a slash-free colon for a URL', () => {
    expect(repositoryLabel('release:2.zip')).toBe('release:2.zip')
  })
})
