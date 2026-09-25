/** Mirrors backend/app/schemas/finding.py */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW'

/** Worst first — used for ordering and for the severity filter row. */
export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

export interface Finding {
  id: number
  repository_id: number
  rule_id: string
  analyzer: string
  title: string
  message: string
  severity: Severity
  confidence: Confidence
  cwe_id: string | null
  owasp_category: string | null
  file_path: string
  line_start: number
  line_end: number
  /** Code from the analysed repository, already redacted server-side.
   *  Rendered as text, never as HTML. */
  snippet: string
  fingerprint: string
  created_at: string
}

export interface FindingListResponse {
  items: Finding[]
  total: number
  /** Counts for the whole repository, unaffected by the severity filter. */
  by_severity: Record<string, number>
  limit: number
  offset: number
}

export interface AnalysisSummary {
  repository_id: number
  findings: number
  by_severity: Record<string, number>
  files_scanned: number
  files_skipped: number
  unparsable_files: number
  truncated: boolean
  duration_ms: number
  analyzed_at: string
}
