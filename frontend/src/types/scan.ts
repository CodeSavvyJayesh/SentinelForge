/** Mirrors backend/app/schemas/scan.py */

export type ScanStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED'

/** A scan that has not finished — the UI polls while one of these is true. */
export const ACTIVE_SCAN_STATUSES: ScanStatus[] = ['QUEUED', 'RUNNING']

export interface Scan {
  id: number
  repository_id: number
  status: ScanStatus
  attempts: number
  started_at: string | null
  finished_at: string | null
  duration_ms: number | null
  files_scanned: number
  files_skipped: number
  unparsable_files: number
  /** What this run concluded, frozen when it ran. */
  total_findings: number
  new_findings: number
  fixed_findings: number
  truncated: boolean
  error_message: string | null
  created_at: string
}

export interface ScanListResponse {
  items: Scan[]
  total: number
  limit: number
  offset: number
}
