/** Read a non-httpOnly cookie. Returns null when absent or unreadable. */
export function readCookie(name: string, source?: string): string | null {
  const jar = source ?? (typeof document === 'undefined' ? '' : document.cookie)
  if (!jar) return null
  for (const part of jar.split(';')) {
    const [rawName, ...rest] = part.trim().split('=')
    if (rawName === name) return decodeURIComponent(rest.join('='))
  }
  return null
}
