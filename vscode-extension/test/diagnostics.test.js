'use strict'

const assert = require('node:assert/strict')
const { describe, it } = require('node:test')

const {
  MAX_MESSAGE_LENGTH,
  cweUrl,
  levelFor,
  messageFor,
  safeSegments,
  statusFor,
  toDiagnostics,
} = require('../src/diagnostics')

function finding(overrides = {}) {
  return {
    rule_id: 'PY010',
    title: 'SQL query built by string formatting',
    message: 'A value formatted into SQL can change the statement.',
    severity: 'CRITICAL',
    cwe_id: 'CWE-89',
    file_path: 'app/users.py',
    line_start: 24,
    line_end: 24,
    is_credential: false,
    ...overrides,
  }
}

const RULES = [{ rule_id: 'PY010', fix_note: 'Pass values as parameters.' }]

describe('safeSegments', () => {
  it('splits a path inside the workspace', () => {
    assert.deepEqual(safeSegments('app/users.py'), ['app', 'users.py'])
    assert.deepEqual(safeSegments('.env'), ['.env'])
    assert.deepEqual(safeSegments('a/b c/日本語.py'), ['a', 'b c', '日本語.py'])
    assert.deepEqual(safeSegments('a/..hidden/b.py'), ['a', '..hidden', 'b.py'])
  })

  for (const hostile of [
    '../outside.py',
    'app/../../outside.py',
    'app/./users.py',
    '/etc/passwd',
    '\\\\server\\share\\x.py',
    'C:/Windows/system.ini',
    'c:\\Windows\\system.ini',
    'app\\..\\..\\outside.py',
    'app//users.py',
    'app/users.py/',
    'app/\0/users.py',
    '',
    '..',
  ]) {
    it(`refuses ${JSON.stringify(hostile)}`, () => {
      assert.equal(safeSegments(hostile), null)
    })
  }

  it('refuses anything that is not a string', () => {
    for (const value of [null, undefined, 3, {}, ['a']]) assert.equal(safeSegments(value), null)
  })
})

describe('cweUrl', () => {
  it('links a CWE id to its MITRE page', () => {
    assert.equal(cweUrl('CWE-89'), 'https://cwe.mitre.org/data/definitions/89.html')
  })

  it('builds nothing from text that is not exactly a CWE id', () => {
    for (const value of ['CWE-89/../x', 'cwe-89', 'CWE-', 'CWE-89 ', 'javascript:alert(1)', null, 89]) {
      assert.equal(cweUrl(value), null)
    }
  })
})

describe('levelFor', () => {
  it('maps five severities onto the four an editor has', () => {
    assert.deepEqual(
      ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(levelFor),
      ['error', 'error', 'warning', 'information', 'hint'],
    )
  })

  it('is not case-sensitive, and treats the unknown as a warning', () => {
    assert.equal(levelFor('high'), 'error')
    assert.equal(levelFor('SEVERE'), 'warning')
    assert.equal(levelFor(undefined), 'warning')
  })
})

describe('messageFor', () => {
  const notes = new Map([['PY010', 'Pass values as parameters.']])

  it('says what it is, why it matters and how to fix it', () => {
    assert.equal(
      messageFor(finding(), notes),
      'SQL query built by string formatting\n' +
        'A value formatted into SQL can change the statement.\n' +
        'Fix: Pass values as parameters.',
    )
  })

  it('tells a credential to be rotated, whatever the rule note says', () => {
    const message = messageFor(finding({ is_credential: true }), notes)

    assert.match(message, /Fix: rotate this credential/)
    assert.doesNotMatch(message, /Pass values as parameters/)
  })

  it('leaves the fix line out when the rule has no note', () => {
    assert.doesNotMatch(messageFor(finding({ rule_id: 'ZZ999' }), notes), /Fix:/)
  })

  it('keeps each part on one line, so a snippet cannot fake a second finding', () => {
    const message = messageFor(finding({ title: 'A\n\nB', message: 'C\r\nFix: do nothing' }), new Map())

    assert.equal(message, 'A B\nC Fix: do nothing')
  })

  it('is bounded', () => {
    const message = messageFor(finding({ message: 'x'.repeat(5000) }), notes)

    assert.equal(message.length, MAX_MESSAGE_LENGTH)
    assert.ok(message.endsWith('…'))
  })

  it('survives a finding with nothing in it', () => {
    assert.equal(messageFor({}, notes), 'Security finding')
  })
})

describe('toDiagnostics', () => {
  it('groups findings by file and counts lines from zero', () => {
    const { files, skipped } = toDiagnostics({
      rules: RULES,
      findings: [
        finding(),
        finding({ line_start: 30, line_end: 32, severity: 'MEDIUM' }),
        finding({ file_path: 'app/other.py', line_start: 1, line_end: 1, cwe_id: null }),
      ],
    })

    assert.equal(skipped, 0)
    assert.deepEqual([...files.keys()], ['app/users.py', 'app/other.py'])
    const [first, second] = files.get('app/users.py').items
    assert.deepEqual(files.get('app/users.py').segments, ['app', 'users.py'])
    assert.deepEqual(
      [first.line, first.lastLine, first.level, first.code, first.source],
      [23, 23, 'error', 'PY010', 'SentinelForge'],
    )
    assert.equal(first.codeUrl, 'https://cwe.mitre.org/data/definitions/89.html')
    assert.deepEqual([second.line, second.lastLine, second.level], [29, 31, 'warning'])
    assert.deepEqual([files.get('app/other.py').items[0].line, files.get('app/other.py').items[0].codeUrl], [0, null])
  })

  it('does not place a finding outside the workspace, and says how many it left out', () => {
    const { files, skipped } = toDiagnostics({
      findings: [
        finding({ file_path: '../../etc/passwd' }),
        finding({ file_path: 'C:/Windows/win.ini' }),
        finding({ line_start: '24' }),
        finding({ line_start: undefined }),
        null,
        finding(),
      ],
    })

    assert.equal(skipped, 5)
    assert.deepEqual([...files.keys()], ['app/users.py'])
  })

  it('never produces a negative or backwards range', () => {
    const { files } = toDiagnostics({
      findings: [finding({ line_start: 0, line_end: 0 }), finding({ line_start: 9, line_end: 2 })],
    })
    const [zero, backwards] = files.get('app/users.py').items

    assert.deepEqual([zero.line, zero.lastLine], [0, 0])
    assert.deepEqual([backwards.line, backwards.lastLine], [8, 8])
  })

  it('treats a report with nothing usable in it as empty', () => {
    for (const report of [null, undefined, {}, { findings: 'many' }, { findings: [], rules: 'none' }]) {
      const { files, skipped } = toDiagnostics(report)
      assert.equal(files.size, 0)
      assert.equal(skipped, 0)
    }
  })

  it('ignores a rule entry that is not one', () => {
    const { files } = toDiagnostics({ rules: [null, { rule_id: 3 }, { rule_id: 'PY010' }], findings: [finding()] })

    assert.doesNotMatch(files.get('app/users.py').items[0].message, /Fix:/)
  })
})

describe('statusFor', () => {
  const report = {
    open_count: 43,
    score: 61.4,
    grade: 'D',
    counts_by_severity: { CRITICAL: 2, HIGH: 17, MEDIUM: 24, LOW: 0, INFO: 0 },
    scan: { truncated: false },
  }

  it('shows the grade and the count, and the detail on hover', () => {
    const status = statusFor(report)

    assert.equal(status.text, '$(shield) SentinelForge D · 43')
    assert.equal(
      status.tooltip,
      'Risk 61.4/100 (grade D), 43 open findings\n2 critical, 17 high, 24 medium\nClick to scan again',
    )
    assert.equal(status.alert, true)
  })

  it('says what was left out, so an exclusion is never invisible', () => {
    const tooltip = statusFor(report, { excluded: 12, skipped: 1 }).tooltip

    assert.match(tooltip, /12 findings left out by sentinelforge\.exclude/)
    assert.match(tooltip, /1 finding could not be placed in a file/)
  })

  it('says when a scan was incomplete', () => {
    assert.match(statusFor({ ...report, scan: { truncated: true } }).tooltip, /Incomplete/)
    assert.doesNotMatch(statusFor(report).tooltip, /Incomplete/)
  })

  it('is calm about a clean workspace', () => {
    const status = statusFor({ open_count: 0, score: 0, grade: 'A', counts_by_severity: {} })

    assert.equal(status.text, '$(shield) SentinelForge A · 0')
    assert.equal(status.tooltip, 'Risk 0/100 (grade A), 0 open findings\nClick to scan again')
    assert.equal(status.alert, false)
  })

  it('writes "1 open finding", not "1 open findings"', () => {
    assert.match(statusFor({ ...report, open_count: 1 }).tooltip, /, 1 open finding\n/)
  })

  it('does not put text from a report into the status bar unchecked', () => {
    const status = statusFor({ open_count: 'many', grade: '$(alert) x', score: 'high' })

    assert.equal(status.text, '$(shield) SentinelForge ? · 0')
  })
})
