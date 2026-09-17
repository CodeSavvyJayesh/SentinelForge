import { describe, expect, it } from 'vitest'

import { normalizeBaseUrl } from './env'

describe('normalizeBaseUrl', () => {
  it('strips trailing slashes', () => {
    expect(normalizeBaseUrl('http://localhost:8000/')).toBe('http://localhost:8000')
    expect(normalizeBaseUrl(' https://api.example.com/base// ')).toBe('https://api.example.com/base')
  })

  it('rejects missing, malformed and non-http values', () => {
    expect(normalizeBaseUrl(undefined)).toBeNull()
    expect(normalizeBaseUrl('   ')).toBeNull()
    expect(normalizeBaseUrl('localhost:8000')).toBeNull()
    expect(normalizeBaseUrl('javascript:alert(1)')).toBeNull()
  })
})
