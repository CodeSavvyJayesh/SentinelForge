import { describe, expect, it } from 'vitest'

import { readCookie } from './cookies'

describe('readCookie', () => {
  it('finds a value among several cookies', () => {
    const jar = 'other=1; sf_csrf=abc123; another=2'
    expect(readCookie('sf_csrf', jar)).toBe('abc123')
  })

  it('decodes encoded values', () => {
    expect(readCookie('sf_csrf', 'sf_csrf=a%20b')).toBe('a b')
  })

  it('returns null when missing or empty', () => {
    expect(readCookie('sf_csrf', 'other=1')).toBeNull()
    expect(readCookie('sf_csrf', '')).toBeNull()
  })
})
