/** Mirrors backend/app/schemas/finding.py */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW'

/** NEW: appeared in the last scan. OPEN: was already there. FIXED: gone now. */
export type FindingStatus = 'NEW' | 'OPEN' | 'FIXED'

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
  status: FindingStatus
  first_seen_scan_id: number | null
  last_seen_scan_id: number | null
  fixed_in_scan_id: number | null
  created_at: string
}

export interface FindingListResponse {
  items: Finding[]
  total: number
  /** Whole-repository counts, unaffected by the filters. Severity counts
   *  exclude fixed findings. */
  by_severity: Record<string, number>
  by_status: Record<string, number>
  limit: number
  offset: number
}
