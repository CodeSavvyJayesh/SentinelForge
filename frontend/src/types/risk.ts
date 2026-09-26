/** Mirrors backend/app/schemas/risk.py */

/** One multiplier, with the reason it applied.
 *
 * Shown rather than hidden: a reader who can see `× 0.4 test path` can
 * disagree with that specific step. A reader shown only a total cannot.
 */
export interface RiskFactor {
  name: string
  value: number
  reason: string
}

export interface FindingRisk {
  finding_id: number
  score: number
  base: number
  factors: RiskFactor[]
  /** The multiplication written out, e.g. "40 base × 0.8 confidence = 32". */
  explanation: string
  title: string
  severity: string
  file_path: string
  line_start: number
}

export type RiskGrade = 'A' | 'B' | 'C' | 'D' | 'F'

export interface RepositoryRisk {
  repository_id: number
  score: number
  grade: RiskGrade
  /** Bumped when a scoring constant changes; two versions are not comparable. */
  policy_version: number
  finding_count: number
  counts_by_severity: Record<string, number>
  top: FindingRisk[]
}

export interface RiskPoint {
  scan_id: number
  score: number
  grade: string
  policy_version: number | null
  total_findings: number
  finished_at: string
}

export interface RiskHistory {
  repository_id: number
  /** Oldest first — a chart reads left to right. */
  points: RiskPoint[]
}

/** What each grade means in words, so the letter is not just decoration. */
export const GRADE_LABELS: Record<RiskGrade, string> = {
  A: 'Nothing outstanding',
  B: 'Minor issues',
  C: 'Worth addressing',
  D: 'Needs attention',
  F: 'Act on this',
}
