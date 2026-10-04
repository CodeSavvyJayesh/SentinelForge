/** Mirrors backend/app/schemas/report.py (ReportExportRead) */

export const REPORT_FORMATS = ['html', 'markdown', 'sarif', 'json'] as const
export type ReportFormat = (typeof REPORT_FORMATS)[number]

/** A rendered report: the document, and what to call it when it is saved. */
export interface ReportExport {
  format: ReportFormat
  filename: string
  media_type: string
  content: string
}

export interface ReportFormatInfo {
  label: string
  /** What the format is for, in a few words, so the choice is not a guess. */
  purpose: string
}

export const REPORT_FORMAT_INFO: Record<ReportFormat, ReportFormatInfo> = {
  html: { label: 'HTML', purpose: 'to read, print or save as PDF' },
  markdown: { label: 'Markdown', purpose: 'to paste into an issue or a README' },
  sarif: { label: 'SARIF', purpose: 'for GitHub code scanning and other tools' },
  json: { label: 'JSON', purpose: 'the same report as data' },
}

/**
 * A name that is safe to hand to the browser's "save as".
 *
 * The API already builds the name from letters, digits and hyphens. This is
 * the same rule applied again on this side, because the name goes straight
 * into a download and the client should not depend on the server having been
 * careful.
 */
export function safeFilename(name: string, format: ReportFormat): string {
  const extension = { html: 'html', markdown: 'md', sarif: 'sarif', json: 'json' }[format]
  const stem = name
    .replace(/\.[A-Za-z0-9]+$/, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80)
  return `${stem || 'sentinelforge-report'}.${extension}`
}
