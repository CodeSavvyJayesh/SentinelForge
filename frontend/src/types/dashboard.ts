/** Mirrors backend/app/schemas/dashboard.py */

import type { RiskGrade } from './risk'

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const
export type SeverityName = (typeof SEVERITIES)[number]

export interface DashboardTotals {
  projects: number
  repositories: number
  /** Repositories with at least one completed scan. The rest have no score. */
  repositories_scanned: number
  scans_completed: number
  open_findings: number
  fixed_findings: number
}

export interface DashboardTrendPoint {
  scan_id: number
  score: number
  grade: string
  total_findings: number
  finished_at: string
}

export interface DashboardRepository {
  repository_id: number
  project_id: number
  project_name: string
  origin: string
  primary_language: string | null
  /** Null until a scan has completed. Never scanned is not the same as clean. */
  score: number | null
  grade: RiskGrade | null
  open_findings: number
  fixed_findings: number
  counts_by_severity: Record<string, number>
  last_scan_at: string | null
  /** Oldest first, as each scan recorded it. */
  trend: DashboardTrendPoint[]
}

export interface DashboardFinding {
  finding_id: number
  repository_id: number
  project_id: number
  project_name: string
  origin: string
  rule_id: string
  title: string
  severity: string
  cwe_id: string | null
  file_path: string
  line_start: number
  score: number
  explanation: string
}

export interface DashboardWeakness {
  cwe_id: string | null
  owasp_category: string | null
  title: string
  count: number
  worst_severity: string
}

export interface DashboardFixes {
  requested: number
  generating: number
  refused: number
  proposed: number
  passed: number
  rejected: number
  not_judged: number
  checking: number
  unchecked: number
  /** passed + rejected: proposals a re-scan gave a verdict on. */
  labelled: number
}

export interface Dashboard {
  generated_at: string
  policy_version: number
  totals: DashboardTotals
  open_by_severity: Record<string, number>
  repositories: DashboardRepository[]
  top_findings: DashboardFinding[]
  weaknesses: DashboardWeakness[]
  fixes: DashboardFixes
}

/** One row of a bar list: a label, a count, and how long to draw the bar. */
export interface BarRow {
  key: string
  label: string
  value: number
  /** 0–100, relative to the largest row — never to an invented maximum. */
  percent: number
  /** A sentence for the hover title and for screen readers. */
  description: string
}

/**
 * Bar length as a share of the largest value in the list.
 *
 * A non-zero value never rounds down to nothing: one finding next to four
 * hundred still gets a visible sliver, because "one" and "none" are the
 * difference a reader is looking for.
 */
export function barPercent(value: number, largest: number): number {
  if (value <= 0 || largest <= 0) return 0
  return Math.max(2, Math.min(100, (value / largest) * 100))
}

function share(value: number, total: number): string {
  if (total <= 0) return '0%'
  const percent = (value / total) * 100
  return percent > 0 && percent < 1 ? 'under 1%' : `${Math.round(percent)}%`
}

function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? '' : 's'}`
}

/** All five severities, worst first, including the ones with nothing in them. */
export function severityRows(counts: Record<string, number>): BarRow[] {
  const values = SEVERITIES.map((severity) => counts[severity] ?? 0)
  const largest = Math.max(...values)
  const total = values.reduce((sum, value) => sum + value, 0)
  return SEVERITIES.map((severity, index) => {
    const value = values[index] ?? 0
    return {
      key: severity,
      label: severity,
      value,
      percent: barPercent(value, largest),
      description: `${severity}: ${plural(value, 'open finding')}, ${share(value, total)} of all open findings`,
    }
  })
}

export function weaknessRows(weaknesses: DashboardWeakness[]): BarRow[] {
  const largest = Math.max(0, ...weaknesses.map((item) => item.count))
  return weaknesses.map((item) => ({
    key: item.cwe_id ?? 'unclassified',
    label: item.cwe_id ? `${item.cwe_id} · ${item.title}` : item.title,
    value: item.count,
    percent: barPercent(item.count, largest),
    description: `${plural(item.count, 'open finding')}, worst severity ${item.worst_severity}${
      item.owasp_category ? `, ${item.owasp_category}` : ''
    }`,
  }))
}

/**
 * What happened to every change that was asked for, in the order it happens.
 *
 * Rows that are zero are left out, except the two verdicts: "0 passed" is a
 * result worth seeing, "0 still generating" is not.
 */
export function fixRows(fixes: DashboardFixes): BarRow[] {
  const rows: { key: string; label: string; value: number; note: string; always?: boolean }[] = [
    {
      key: 'passed',
      label: 'Passed the re-scan',
      value: fixes.passed,
      note: 'the finding was gone, nothing new appeared, and the change was not a deletion',
      always: true,
    },
    {
      key: 'rejected',
      label: 'Rejected by the re-scan',
      value: fixes.rejected,
      note: 'the finding was still there, something new appeared, or the code was deleted',
      always: true,
    },
    {
      key: 'not_judged',
      label: 'Could not be checked',
      value: fixes.not_judged,
      note: 'the stored code had changed, so the re-scan says nothing about the change',
    },
    {
      key: 'unchecked',
      label: 'Never checked',
      value: fixes.unchecked,
      note: 'proposed before automatic checking existed',
    },
    {
      key: 'refused',
      label: 'No change proposed',
      value: fixes.refused,
      note: "the model's answer was thrown away before it became a proposal",
    },
    {
      key: 'in_progress',
      label: 'In progress',
      value: fixes.generating + fixes.checking,
      note: 'being generated or being checked right now',
    },
  ]
  const largest = Math.max(...rows.map((row) => row.value))
  return rows
    .filter((row) => row.always || row.value > 0)
    .map((row) => ({
      key: row.key,
      label: row.label,
      value: row.value,
      percent: barPercent(row.value, largest),
      description: `${row.label}: ${row.value} of ${plural(fixes.requested, 'request')} — ${row.note}`,
    }))
}

/** Share of judged proposals that passed, or null when nothing has a verdict. */
export function passRate(fixes: DashboardFixes): number | null {
  if (fixes.labelled <= 0) return null
  return Math.round((fixes.passed / fixes.labelled) * 100)
}

/** The file name of an upload, or the last two segments of a clone URL. */
export function repositoryLabel(origin: string): string {
  const trimmed = origin.replace(/\.git$/, '').replace(/\/+$/, '')
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return trimmed
  const segments = trimmed.split('/').filter(Boolean)
  return segments.slice(-2).join('/')
}
