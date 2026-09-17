/**
 * Runtime configuration read from Vite environment variables (frontend/.env).
 * Nothing here may be secret: every VITE_* value is shipped to the browser.
 */

/** Validate and normalise an API base URL. Returns null when missing or invalid. */
export function normalizeBaseUrl(value: string | undefined): string | null {
  const trimmed = value?.trim()
  if (!trimmed) return null
  try {
    const url = new URL(trimmed)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null
    return url.toString().replace(/\/+$/, '')
  } catch {
    return null
  }
}

export const appConfig = {
  apiBaseUrl: normalizeBaseUrl(import.meta.env.VITE_API_BASE_URL),
} as const
