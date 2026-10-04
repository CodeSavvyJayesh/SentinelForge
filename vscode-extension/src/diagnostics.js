'use strict'

/**
 * Turning a SentinelForge report into what an editor shows.
 *
 * Nothing here touches the VS Code API, the file system or a process, so all
 * of it can be tested with plain Node. The report is treated as untrusted: it
 * is produced by a scanner reading a folder somebody else may have written,
 * and a file path in it is a string a repository chose.
 */

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

/** Editor severities, by name. The extension maps these onto vscode's enum. */
const LEVELS = {
  CRITICAL: 'error',
  HIGH: 'error',
  MEDIUM: 'warning',
  LOW: 'information',
  INFO: 'hint',
}

const SOURCE = 'SentinelForge'
const MAX_MESSAGE_LENGTH = 1200

function levelFor(severity) {
  return LEVELS[String(severity).toUpperCase()] ?? 'warning'
}

/**
 * A repository-relative path as segments, or null if it is not one.
 *
 * The scanner only ever reports paths inside the folder it was given. This is
 * checked again here rather than assumed: the segments are joined onto the
 * workspace folder, and a path that climbed out of it (`../../x`), was
 * absolute, or named a drive would attach a finding to a file outside the
 * workspace.
 */
function safeSegments(filePath) {
  if (typeof filePath !== 'string' || filePath === '') return null
  if (filePath.includes('\0')) return null
  if (/^[A-Za-z]:/.test(filePath)) return null
  const segments = filePath.split('/')
  for (const segment of segments) {
    // An empty segment also covers a leading slash (an absolute path) and a
    // doubled or trailing one.
    if (segment === '' || segment === '.' || segment === '..') return null
    if (segment.includes('\\')) return null
  }
  return segments
}

/** The MITRE page for a CWE id, only when the id is exactly one. */
function cweUrl(cweId) {
  const match = /^CWE-(\d{1,6})$/.exec(typeof cweId === 'string' ? cweId : '')
  return match ? `https://cwe.mitre.org/data/definitions/${match[1]}.html` : null
}

function oneLine(value) {
  return typeof value === 'string' ? value.replace(/\s+/g, ' ').trim() : ''
}

function clip(text) {
  return text.length > MAX_MESSAGE_LENGTH ? `${text.slice(0, MAX_MESSAGE_LENGTH - 1)}…` : text
}

/**
 * What the hover and the Problems panel say.
 *
 * First line: what it is. Then why, then how to fix it — the fix is this
 * project's own note for the rule, which is the part a developer came for.
 * A credential gets its own advice: rotate it, because an edit does not
 * un-leak it.
 */
function messageFor(finding, fixNotes) {
  const lines = [oneLine(finding.title) || 'Security finding']
  const why = oneLine(finding.message)
  if (why) lines.push(why)
  if (finding.is_credential === true) {
    lines.push('Fix: rotate this credential. Removing the line does not un-leak it.')
  } else {
    const fix = oneLine(fixNotes.get(finding.rule_id))
    if (fix) lines.push(`Fix: ${fix}`)
  }
  return clip(lines.join('\n'))
}

function isInteger(value) {
  return Number.isInteger(value)
}

/**
 * Findings grouped by file, as plain objects ready to become diagnostics.
 *
 * Returns `{ files: Map<key, { segments, items }>, skipped }`. A finding with
 * a path that is not safely inside the workspace, or without a usable line, is
 * counted in `skipped` rather than shown somewhere it does not belong.
 */
function toDiagnostics(report) {
  const fixNotes = new Map()
  for (const rule of Array.isArray(report?.rules) ? report.rules : []) {
    if (rule && typeof rule.rule_id === 'string' && typeof rule.fix_note === 'string') {
      fixNotes.set(rule.rule_id, rule.fix_note)
    }
  }

  const files = new Map()
  let skipped = 0
  for (const finding of Array.isArray(report?.findings) ? report.findings : []) {
    const segments = finding && safeSegments(finding.file_path)
    if (!segments || !isInteger(finding.line_start)) {
      skipped += 1
      continue
    }
    // Reports count lines from 1; an editor counts from 0.
    const line = Math.max(0, finding.line_start - 1)
    const lastLine = isInteger(finding.line_end) ? Math.max(line, finding.line_end - 1) : line
    const key = segments.join('/')
    if (!files.has(key)) files.set(key, { segments, items: [] })
    files.get(key).items.push({
      line,
      lastLine,
      level: levelFor(finding.severity),
      message: messageFor(finding, fixNotes),
      code: oneLine(finding.rule_id) || 'finding',
      codeUrl: cweUrl(finding.cwe_id),
      source: SOURCE,
    })
  }
  return { files, skipped }
}

function plural(count, noun) {
  return `${count} ${noun}${count === 1 ? '' : 's'}`
}

/** The status bar item: a grade and a count, and the detail on hover. */
function statusFor(report, { excluded = 0, skipped = 0 } = {}) {
  const open = isInteger(report?.open_count) ? report.open_count : 0
  const grade = /^[A-F]$/.test(String(report?.grade)) ? report.grade : '?'
  const score = typeof report?.score === 'number' ? report.score : 0
  const counts = report?.counts_by_severity ?? {}
  const breakdown = SEVERITIES.filter((severity) => isInteger(counts[severity]) && counts[severity] > 0)
    .map((severity) => `${counts[severity]} ${severity.toLowerCase()}`)
    .join(', ')

  const tooltip = [`Risk ${score}/100 (grade ${grade}), ${plural(open, 'open finding')}`]
  if (breakdown) tooltip.push(breakdown)
  if (excluded > 0) tooltip.push(`${plural(excluded, 'finding')} left out by sentinelforge.exclude`)
  if (skipped > 0) tooltip.push(`${plural(skipped, 'finding')} could not be placed in a file`)
  if (report?.scan?.truncated === true) {
    tooltip.push('Incomplete: the analyser stopped at its limit on findings')
  }
  tooltip.push('Click to scan again')

  return {
    text: `$(shield) SentinelForge ${grade} · ${open}`,
    tooltip: tooltip.join('\n'),
    // Worth a second look at a glance: anything at HIGH or above.
    alert: (counts.CRITICAL ?? 0) + (counts.HIGH ?? 0) > 0,
  }
}

module.exports = {
  LEVELS,
  MAX_MESSAGE_LENGTH,
  SEVERITIES,
  SOURCE,
  cweUrl,
  levelFor,
  messageFor,
  safeSegments,
  statusFor,
  toDiagnostics,
}
