import { describe, expect, it } from 'vitest'

import { tokenStore } from './tokenStore'

describe('tokenStore', () => {
  it('holds the token only in memory', () => {
    tokenStore.set('abc')
    expect(tokenStore.get()).toBe('abc')
    tokenStore.clear()
    expect(tokenStore.get()).toBeNull()
  })

  it('never writes to browser storage', () => {
    const storage = globalThis as { localStorage?: unknown; sessionStorage?: unknown }
    tokenStore.set('secret')
    // Nothing to assert against in Node, so assert the contract explicitly:
    // the module exposes no persistence hooks at all.
    expect(Object.keys(tokenStore).sort()).toEqual(['clear', 'get', 'set'])
    expect(storage.localStorage).toBeUndefined()
    tokenStore.clear()
  })
})
