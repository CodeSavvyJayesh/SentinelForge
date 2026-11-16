'use strict'

const assert = require('node:assert/strict')
const { describe, it } = require('node:test')

const {
  CHECKED_NOTE,
  FixResultError,
  MODES,
  STATUSES,
  fixInfoFor,
  isFingerprint,
  isMode,
  parseFixResult,
  planEdits,
  proposedText,
  verifiedDetail,
} = require('../src/fixes')

const FINGERPRINT = 'a'.repeat(64)

/** What `python -m app.cli fix --json` writes for a weak hash, as the real command wrote it. */
function result(overrides = {}) {
  return {
    schema: 1,
    status: 'verified',
    source: 'builtin',
    title: 'Use SHA-256 instead of a broken hash',
    rationale: 'MD5 and SHA-1 are collision-broken; SHA-256 is not.',
    caution: 'Values hashed before this change will not match values hashed after it.',
    reason: '',
    diff: '--- a/app/main.py\n+++ b/app/main.py\n',
    edits: [
      {
        first_line: 5,
        last_line: 5,
        old: ['    return hashlib.md5(value).hexdigest()\n'],
        new: ['    return hashlib.sha256(value).hexdigest()\n'],
      },
    ],
    model: null,
    ...overrides,
  }
}

const SOURCE = 'import hashlib\n\n\ndef digest(value):\n    return hashlib.md5(value).hexdigest()\n'
const EDITOR_LINES = ['import hashlib', '', '', 'def digest(value):', '    return hashlib.md5(value).hexdigest()', '']

describe('isFingerprint and isMode', () => {
  it('accept exactly what the scanner produces', () => {
    assert.equal(isFingerprint(FINGERPRINT), true)
    assert.equal(isFingerprint('A'.repeat(64)), false)
    assert.equal(isFingerprint('a'.repeat(63)), false)
    assert.equal(isFingerprint(`${'a'.repeat(64)}\n`), false)
    assert.equal(isFingerprint(42), false)
    assert.equal(isMode('builtin'), true)
    assert.equal(isMode('model'), true)
    assert.equal(isMode('--apply'), false)
  })
})

describe('fixInfoFor', () => {
  it("offers the report's own title for a rule with a built-in fix", () => {
    const info = fixInfoFor({ rule_id: 'PY007', fingerprint: FINGERPRINT }, { PY007: 'Use SHA-256' })

    assert.deepEqual(info, { fingerprint: FINGERPRINT, credential: false, builtinTitle: 'Use SHA-256' })
  })

  it('offers no built-in fix for a rule without one, and still names the finding', () => {
    const info = fixInfoFor({ rule_id: 'PY010', fingerprint: FINGERPRINT }, { PY007: 'Use SHA-256' })

    assert.equal(info.builtinTitle, null)
    assert.equal(info.fingerprint, FINGERPRINT)
  })

  it('marks a credential, which is rotated and never edited', () => {
    const info = fixInfoFor({ rule_id: 'SEC001', fingerprint: FINGERPRINT, is_credential: true }, {})

    assert.equal(info.credential, true)
  })

  it('offers nothing for a finding without a usable fingerprint', () => {
    assert.equal(fixInfoFor({ rule_id: 'PY007' }, { PY007: 'x' }), null)
    assert.equal(fixInfoFor({ rule_id: 'PY007', fingerprint: '../../etc' }, { PY007: 'x' }), null)
    assert.equal(fixInfoFor(null, {}), null)
  })

  it('is not fooled by a rule id that names an inherited property', () => {
    const info = fixInfoFor({ rule_id: 'constructor', fingerprint: FINGERPRINT }, {})

    assert.equal(info.builtinTitle, null)
  })

  it('works with a report from a scanner that sends no list of fixes', () => {
    assert.equal(fixInfoFor({ rule_id: 'PY007', fingerprint: FINGERPRINT }, undefined).builtinTitle, null)
  })
})

describe('parseFixResult', () => {
  it('reads a verified fix', () => {
    const parsed = parseFixResult(result())

    assert.equal(parsed.status, STATUSES.VERIFIED)
    assert.equal(parsed.source, MODES.BUILTIN)
    assert.equal(parsed.title, 'Use SHA-256 instead of a broken hash')
    assert.deepEqual(parsed.edits, [
      {
        firstLine: 5,
        lastLine: 5,
        old: ['    return hashlib.md5(value).hexdigest()\n'],
        new: ['    return hashlib.sha256(value).hexdigest()\n'],
      },
    ])
  })

  it('never gives edits to a change that did not pass', () => {
    const parsed = parseFixResult(result({ status: 'rejected', reason: 'A new finding appeared.' }))

    assert.deepEqual(parsed.edits, [])
    assert.equal(parsed.reason, 'A new finding appeared.')
  })

  it('reads which model wrote a change', () => {
    const parsed = parseFixResult(result({ source: 'model', model: { model: 'qwen2.5-coder:7b' } }))

    assert.equal(parsed.source, MODES.MODEL)
    assert.equal(parsed.model, 'qwen2.5-coder:7b')
  })

  it('keeps titles and reasons to one short line', () => {
    const parsed = parseFixResult(result({ title: `Line one\nline two ${'x'.repeat(300)}` }))

    assert.equal(parsed.title.includes('\n'), false)
    assert.ok(parsed.title.length <= 120)
  })

  const refusals = {
    'a result that is not an object': null,
    'another schema': result({ schema: 2 }),
    'an unknown status': result({ status: 'probably fine' }),
    'a verified result with nothing to apply': result({ edits: [] }),
    'an edit that names impossible lines': result({ edits: [{ first_line: 0, last_line: 0, old: ['x'], new: ['y'] }] }),
    'an edit whose old lines do not match its range': result({
      edits: [{ first_line: 5, last_line: 6, old: ['x\n'], new: ['y\n'] }],
    }),
    'an edit that changes nothing': result({ edits: [{ first_line: 5, last_line: 4, old: [], new: [] }] }),
    'an edit with lines that are not text': result({ edits: [{ first_line: 5, last_line: 5, old: [5], new: ['y'] }] }),
    'overlapping edits': result({
      edits: [
        { first_line: 5, last_line: 6, old: ['a\n', 'b\n'], new: ['c\n'] },
        { first_line: 6, last_line: 6, old: ['b\n'], new: ['d\n'] },
      ],
    }),
    'too many edits': result({
      edits: Array.from({ length: 201 }, (_, index) => ({
        first_line: index + 1,
        last_line: index + 1,
        old: ['a\n'],
        new: ['b\n'],
      })),
    }),
  }
  for (const [name, data] of Object.entries(refusals)) {
    it(`refuses ${name}`, () => {
      assert.throws(() => parseFixResult(data), FixResultError)
    })
  }
})

describe('planEdits', () => {
  const edits = parseFixResult(result()).edits

  it('replaces whole lines, from the start of one to the start of the next', () => {
    const plan = planEdits(EDITOR_LINES, edits)

    assert.deepEqual(plan, {
      ok: true,
      replacements: [
        {
          start: { line: 4, character: 0 },
          end: { line: 5, character: 0 },
          text: '    return hashlib.sha256(value).hexdigest()\n',
        },
      ],
    })
  })

  it('refuses when a line it replaces has changed since the fix was checked', () => {
    const edited = [...EDITOR_LINES]
    edited[4] = '    return hashlib.md5(value).digest()'

    assert.deepEqual(planEdits(edited, edits), { ok: false })
  })

  it('refuses when the file has become shorter than the edit', () => {
    assert.deepEqual(planEdits(EDITOR_LINES.slice(0, 3), edits), { ok: false })
  })

  it('compares lines without their endings, as an editor holds them', () => {
    const crlf = parseFixResult(
      result({
        edits: [
          {
            first_line: 5,
            last_line: 5,
            old: ['    return hashlib.md5(value).hexdigest()\r\n'],
            new: ['    return hashlib.sha256(value).hexdigest()\r\n'],
          },
        ],
      }),
    ).edits

    assert.equal(planEdits(EDITOR_LINES, crlf).ok, true)
  })

  it('runs to the end of the document when the last line has no ending', () => {
    const lines = ['import hashlib', 'value = hashlib.md5(b"x")']
    const last = parseFixResult(
      result({ edits: [{ first_line: 2, last_line: 2, old: ['value = hashlib.md5(b"x")'], new: ['value = hashlib.sha256(b"x")'] }] }),
    ).edits

    assert.deepEqual(planEdits(lines, last).replacements[0], {
      start: { line: 1, character: 0 },
      end: { line: 1, character: 25 },
      text: 'value = hashlib.sha256(b"x")',
    })
  })
})

describe('proposedText', () => {
  it('is the file with the change made, endings kept', () => {
    const edits = parseFixResult(result()).edits

    assert.equal(proposedText(SOURCE, edits), SOURCE.replace('md5', 'sha256'))
  })

  it('is null when the file is no longer the one that was checked', () => {
    const edits = parseFixResult(result()).edits

    assert.equal(proposedText(SOURCE.replace('md5(value)', 'md5(other)'), edits), null)
  })
})

describe('verifiedDetail', () => {
  it('says what changed, what to watch for, and what the check does not prove', () => {
    const detail = verifiedDetail(parseFixResult(result()))

    assert.match(detail, /collision-broken/)
    assert.match(detail, /Before you accept it: Values hashed before/)
    assert.ok(detail.includes(CHECKED_NOTE))
    assert.doesNotMatch(detail, /local model/)
  })

  it('says when the local model wrote the change', () => {
    const detail = verifiedDetail(parseFixResult(result({ source: 'model', model: { model: 'qwen2.5-coder:7b' } })))

    assert.match(detail, /Written by the local model \(qwen2\.5-coder:7b\)\. Read the change/)
  })
})
