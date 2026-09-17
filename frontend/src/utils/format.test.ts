import { describe, expect, it } from 'vitest'

import { EMPTY_VALUE, formatDateTime, formatLatency } from './format'

describe('formatLatency', () => {
  it('formats small and large values', () => {
    expect(formatLatency(3.456)).toBe('3.5 ms')
    expect(formatLatency(22.11)).toBe('22 ms')
  })

  it('never invents a number for missing values', () => {
    expect(formatLatency(null)).toBe(EMPTY_VALUE)
    expect(formatLatency(Number.NaN)).toBe(EMPTY_VALUE)
  })
})

describe('formatDateTime', () => {
  it('returns the placeholder for missing or invalid input', () => {
    expect(formatDateTime(null)).toBe(EMPTY_VALUE)
    expect(formatDateTime('not-a-date')).toBe(EMPTY_VALUE)
  })

  it('formats a valid ISO timestamp', () => {
    expect(formatDateTime('2026-09-17T10:00:00Z', 'en-GB')).not.toBe(EMPTY_VALUE)
  })
})
