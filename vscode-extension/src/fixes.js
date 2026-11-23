'use strict'

/**
 * Reading the result of `python -m app.cli fix`, and turning it into an edit.
 *
 * Like `diagnostics.js`, nothing here touches the VS Code API, the file system
 * or a process. The result is treated as untrusted for the same reason the
 * report is: it was produced from a folder somebody else may have written,
 * and — when the local model was asked — partly by a language model.
 *
 * The one thing this file decides is whether an edit may be made at all. A
 * change is only ever applied when three things hold together: the scanner
 * said it passed its re-scan, the edits are well formed, and every line the
 * edits replace still reads exactly as it did when the change was checked.
 */

const MODES = Object.freeze({ BUILTIN: 'builtin', MODEL: 'model' })
const STATUSES = Object.freeze({ VERIFIED: 'verified', REJECTED: 'rejected', NO_FIX: 'no_fix' })

const FINGERPRINT = /^[0-9a-f]{64}$/
const MAX_TITLE_LENGTH = 120
const MAX_TEXT_LENGTH = 1200
const MAX_EDITS = 200
const MAX_EDIT_LINES = 2000

const CHECKED_NOTE =
  'Checked by scanning a copy with this change applied: the finding is gone and nothing new ' +
  'was found. That says the scanner no longer detects it. It does not say the program behaves ' +
  'the same — nothing in the workspace was run.'

class FixResultError extends Error {
  constructor(message) {
    super(message)
    this.name = 'FixResultError'
  }
}

function isFingerprint(value) {
  return typeof value === 'string' && FINGERPRINT.test(value)
}

function isMode(value) {
  return value === MODES.BUILTIN || value === MODES.MODEL
}

function oneLine(value, limit) {
  if (typeof value !== 'string') return ''
  const text = value.replace(/\s+/g, ' ').trim()
  return text.length > limit ? `${text.slice(0, limit - 1)}…` : text
}

/**
 * What a finding in a report can be offered, or null for none.
 *
 * `quickFixes` is the report's own list of rules that have a built-in fix, so
 * the extension keeps no list to fall out of date with the scanner.
 */
function fixInfoFor(finding, quickFixes) {
  if (!finding || !isFingerprint(finding.fingerprint)) return null
  const title =
    quickFixes && typeof quickFixes === 'object' && typeof finding.rule_id === 'string'
      ? oneLine(Object.hasOwn(quickFixes, finding.rule_id) ? quickFixes[finding.rule_id] : '', MAX_TITLE_LENGTH)
      : ''
  return {
    fingerprint: finding.fingerprint,
    // A leaked credential is rotated, not edited. No fix of either kind.
    credential: finding.is_credential === true,
    builtinTitle: title || null,
  }
}

function isLineList(value) {
  return (
    Array.isArray(value) && value.length <= MAX_EDIT_LINES && value.every((line) => typeof line === 'string')
  )
}

function parseEdit(edit) {
  if (edit === null || typeof edit !== 'object') throw new FixResultError('An edit is not an object.')
  const { first_line: first, last_line: last, old, new: replacement } = edit
  if (!Number.isInteger(first) || !Number.isInteger(last) || first < 1 || last < first - 1) {
    throw new FixResultError('An edit names lines that cannot exist.')
  }
  if (!isLineList(old) || !isLineList(replacement)) {
    throw new FixResultError('An edit does not say what it replaces, or with what.')
  }
  if (old.length !== last - first + 1) {
    throw new FixResultError('An edit replaces a different number of lines than it names.')
  }
  if (old.length === 0 && replacement.length === 0) {
    throw new FixResultError('An edit changes nothing.')
  }
  return { firstLine: first, lastLine: last, old, new: replacement }
}

/**
 * The scanner's answer, checked and reduced to what the editor uses.
 *
 * Throws `FixResultError` for anything that is not the agreed shape. A result
 * that claims to be verified and carries no edits is refused here rather than
 * shown as a fix with nothing to apply.
 */
function parseFixResult(data) {
  if (data === null || typeof data !== 'object' || data.schema !== 1) {
    throw new FixResultError('The scanner wrote a result this extension does not understand.')
  }
  if (!Object.values(STATUSES).includes(data.status)) {
    throw new FixResultError('The scanner wrote a result with an unknown status.')
  }
  const rawEdits = Array.isArray(data.edits) ? data.edits : []
  if (rawEdits.length > MAX_EDITS) throw new FixResultError('The change has too many edits to apply.')
  const edits = rawEdits.map(parseEdit).sort((a, b) => a.firstLine - b.firstLine)
  for (let index = 1; index < edits.length; index += 1) {
    // Edits are applied independently, so two that touch the same line would
    // each be checked against text the other one has already replaced.
    if (edits[index].firstLine <= edits[index - 1].lastLine) {
      throw new FixResultError('Two edits in the change overlap.')
    }
  }
  const verified = data.status === STATUSES.VERIFIED
  if (verified && edits.length === 0) {
    throw new FixResultError('The scanner reported a fix with nothing to apply.')
  }
  const model = data.model && typeof data.model === 'object' ? oneLine(data.model.model, 80) : ''
  return {
    status: data.status,
    source: data.source === MODES.MODEL ? MODES.MODEL : MODES.BUILTIN,
    title: oneLine(data.title, MAX_TITLE_LENGTH) || 'Proposed change',
    rationale: oneLine(data.rationale, MAX_TEXT_LENGTH),
    caution: oneLine(data.caution, MAX_TEXT_LENGTH),
    reason: oneLine(data.reason, MAX_TEXT_LENGTH),
    diff: typeof data.diff === 'string' ? data.diff : '',
    // Only a change that passed is ever given edits to apply.
    edits: verified ? edits : [],
    model,
  }
}

function withoutEnding(line) {
  return line.replace(/(?:\r\n|\n|\r)$/, '')
}

/**
 * Where each edit goes in a document, or the reason it cannot go anywhere.
 *
 * `lines` is the document as the editor holds it: one string per line, without
 * line endings. An edit is placed only if every line it replaces is still
 * exactly what the scanner checked — compared without line endings, because an
 * editor keeps one kind of ending in memory whatever the file has on disk.
 *
 * Returns `{ ok: true, replacements }`, each replacement a range in editor
 * coordinates (lines and characters counted from 0) and its new text, or
 * `{ ok: false }` when the document is not the file that was checked.
 */
function planEdits(lines, edits) {
  const replacements = []
  const lineCount = lines.length
  const end = { line: Math.max(0, lineCount - 1), character: lineCount > 0 ? lines[lineCount - 1].length : 0 }
  for (const edit of edits) {
    const start = edit.firstLine - 1
    if (start + edit.old.length > lineCount) return { ok: false }
    for (let offset = 0; offset < edit.old.length; offset += 1) {
      if (withoutEnding(edit.old[offset]) !== lines[start + offset]) return { ok: false }
    }
    const after = start + edit.old.length
    replacements.push({
      // Whole lines, ending included: from the start of the first to the start
      // of the line after the last. Past the last line there is no "line
      // after", so the range runs to the end of the document instead.
      start: start < lineCount ? { line: start, character: 0 } : end,
      end: after < lineCount ? { line: after, character: 0 } : end,
      text: edit.new.join(''),
    })
  }
  return { ok: true, replacements }
}

/**
 * The whole document with the edits made, for showing beside the original.
 * Returns null when `planEdits` would refuse.
 */
function proposedText(text, edits) {
  const pieces = text.match(/[^\r\n]*(?:\r\n|\n|\r)|[^\r\n]+$/g) ?? []
  const lines = pieces.map(withoutEnding)
  // An editor counts one more line than there are line endings.
  const editorLines = text === '' || /(?:\r\n|\n|\r)$/.test(text) ? [...lines, ''] : lines
  if (!planEdits(editorLines, edits).ok) return null
  const result = [...pieces]
  for (const edit of [...edits].sort((a, b) => b.firstLine - a.firstLine)) {
    result.splice(edit.firstLine - 1, edit.old.length, ...edit.new)
  }
  return result.join('')
}

/** What the "apply this?" question says under its title. */
function verifiedDetail(result) {
  const parts = []
  if (result.rationale) parts.push(result.rationale)
  if (result.caution) parts.push(`Before you accept it: ${result.caution}`)
  parts.push(CHECKED_NOTE)
  if (result.source === MODES.MODEL) {
    parts.push(
      `Written by the local model${result.model ? ` (${result.model})` : ''}. Read the change before applying it.`,
    )
  }
  return parts.join('\n\n')
}

module.exports = {
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
}
