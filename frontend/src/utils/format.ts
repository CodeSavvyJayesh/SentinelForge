/** Display helpers. Missing values render as an em dash, never as a fake number. */

export const EMPTY_VALUE = '—'

export function formatLatency(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return EMPTY_VALUE
  return ms < 10 ? `${ms.toFixed(1)} ms` : `${Math.round(ms)} ms`
}

export function formatDateTime(iso: string | null | undefined, locale?: string): string {
  if (!iso) return EMPTY_VALUE
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return EMPTY_VALUE
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'medium' }).format(date)
}

/** Human-readable byte size. 0 is a real value, not a missing one. */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes) || bytes < 0) {
    return EMPTY_VALUE
  }
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = bytes / 1024
  let unitIndex = 0
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024
    unitIndex += 1
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unitIndex]}`
}

/** A short commit hash. Anything that is not a hash is left alone. */
export function formatCommit(hash: string | null | undefined): string {
  if (!hash) return EMPTY_VALUE
  return hash.length > 10 ? hash.slice(0, 10) : hash
}

/** Percentage shares of a language breakdown, biggest first. */
export function toLanguageShares(
  breakdown: Record<string, number> | null | undefined,
): { language: string; bytes: number; percent: number }[] {
  if (!breakdown) return []
  const total = Object.values(breakdown).reduce((sum, value) => sum + value, 0)
  if (total <= 0) return []
  return Object.entries(breakdown)
    .map(([language, bytes]) => ({ language, bytes, percent: (bytes / total) * 100 }))
    .sort((a, b) => b.bytes - a.bytes)
}
