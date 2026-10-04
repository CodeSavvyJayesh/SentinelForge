import { describe, expect, it } from 'vitest'

import { createApiClient, type FetchLike } from './apiClient'
import { createReportService, REPORT_TIMEOUT_MS } from './reportService'
import type { ReportExport } from '../types/report'
import { REPORT_FORMATS, REPORT_FORMAT_INFO, safeFilename } from '../types/report'

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
  return { service: createReportService(client), calls }
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const MARKDOWN: ReportExport = {
  format: 'markdown',
  filename: 'sentinelforge-payments-20261004.md',
  media_type: 'text/markdown; charset=utf-8',
  content: '# Security report: Payments\n',
}

describe('reportService', () => {
  it('asks for one repository in one format, as the signed-in user', async () => {
    const { service, calls } = recordingService([json(MARKDOWN)])

    const result = await service.export(7, 'markdown')

    expect(calls).toHaveLength(1)
    expect(calls[0]?.url).toBe('http://api.test/api/v1/repositories/7/report/export?format=markdown')
    expect(new Headers(calls[0]?.init.headers).get('Authorization')).toBe('Bearer token-1')
    expect(result.filename).toBe('sentinelforge-payments-20261004.md')
    expect(result.content).toContain('# Security report')
  })

  it('asks for the envelope, never for a file the browser would navigate to', async () => {
    const { service, calls } = recordingService([json(MARKDOWN)])

    await service.export(7, 'html')

    expect(calls[0]?.url).not.toContain('download')
    expect(calls[0]?.url).toContain('format=html')
  })

  it('says a repository has not been scanned instead of returning an empty report', async () => {
    const { service } = recordingService([
      json({ error: { code: 'REPORT_NOT_AVAILABLE', message: 'Scan it first.' } }, 409),
    ])

    await expect(service.export(7, 'html')).rejects.toMatchObject({
      code: 'REPORT_NOT_AVAILABLE',
      status: 409,
    })
  })

  it('surfaces somebody else’s repository as not found', async () => {
    const { service } = recordingService([
      json({ error: { code: 'REPOSITORY_NOT_FOUND', message: 'Repository not found' } }, 404),
    ])

    await expect(service.export(999, 'sarif')).rejects.toMatchObject({ status: 404 })
  })

  it('allows a large report longer than an ordinary request', () => {
    expect(REPORT_TIMEOUT_MS > 10_000).toBe(true)
  })
})

describe('report formats', () => {
  it('offers all four, the readable one first', () => {
    expect(REPORT_FORMATS).toEqual(['html', 'markdown', 'sarif', 'json'])
    for (const format of REPORT_FORMATS) {
      expect(REPORT_FORMAT_INFO[format].label).not.toBe('')
      expect(REPORT_FORMAT_INFO[format].purpose).not.toBe('')
    }
  })
})

describe('safeFilename', () => {
  it('keeps the name the API chose', () => {
    expect(safeFilename('sentinelforge-payments-20261004.md', 'markdown')).toBe(
      'sentinelforge-payments-20261004.md',
    )
  })

  it('takes the extension from the format, not from the name', () => {
    expect(safeFilename('report.exe', 'html')).toBe('report.html')
    expect(safeFilename('report', 'sarif')).toBe('report.sarif')
    expect(safeFilename('report.html', 'json')).toBe('report.json')
  })

  it('drops anything that could leave the download folder', () => {
    expect(safeFilename('../../etc/passwd', 'markdown')).toBe('etc-passwd.md')
    expect(safeFilename('C:\\Users\\me\\x.md', 'markdown')).toBe('c-users-me-x.md')
    expect(safeFilename('a b\r\nc.md', 'markdown')).toBe('a-b-c.md')
  })

  it('falls back to a plain name when nothing usable is left', () => {
    expect(safeFilename('', 'html')).toBe('sentinelforge-report.html')
    expect(safeFilename('???.html', 'html')).toBe('sentinelforge-report.html')
  })

  it('bounds the length', () => {
    expect(safeFilename(`${'a'.repeat(300)}.md`, 'markdown')).toBe(`${'a'.repeat(80)}.md`)
  })
})
