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
