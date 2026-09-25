import { describe, expect, it } from 'vitest'

import {
  EMPTY_VALUE,
  formatBytes,
  formatCommit,
  formatDateTime,
  formatLatency,
  toLanguageShares,
} from './format'

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

describe('formatBytes', () => {
  it('formats each unit', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(512)).toBe('512 B')
    expect(formatBytes(2048)).toBe('2.0 KB')
    expect(formatBytes(5 * 1024 * 1024)).toBe('5.0 MB')
    expect(formatBytes(2 * 1024 * 1024 * 1024)).toBe('2.0 GB')
  })

  it('never invents a number for a missing value', () => {
    expect(formatBytes(null)).toBe(EMPTY_VALUE)
    expect(formatBytes(undefined)).toBe(EMPTY_VALUE)
    expect(formatBytes(Number.NaN)).toBe(EMPTY_VALUE)
    expect(formatBytes(-5)).toBe(EMPTY_VALUE)
  })

  it('treats zero as a real value, not a missing one', () => {
    expect(formatBytes(0)).not.toBe(EMPTY_VALUE)
  })
})

describe('formatCommit', () => {
  it('shortens a full hash', () => {
    expect(formatCommit('0123456789abcdef0123456789abcdef01234567')).toBe('0123456789')
  })

  it('leaves short values alone and handles nothing', () => {
    expect(formatCommit('abc123')).toBe('abc123')
    expect(formatCommit(null)).toBe(EMPTY_VALUE)
  })
})

describe('toLanguageShares', () => {
  it('turns bytes into percentages, biggest first', () => {
    const shares = toLanguageShares({ YAML: 250, Python: 750 })

    expect(shares.map((share) => share.language)).toEqual(['Python', 'YAML'])
    expect(Math.round(shares[0]?.percent ?? 0)).toBe(75)
    expect(Math.round(shares[1]?.percent ?? 0)).toBe(25)
  })

  it('returns nothing for empty or missing data', () => {
    expect(toLanguageShares(null)).toEqual([])
    expect(toLanguageShares({})).toEqual([])
    expect(toLanguageShares({ Python: 0 })).toEqual([])
  })
})
