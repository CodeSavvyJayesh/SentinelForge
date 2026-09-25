import { useEffect, useState } from 'react'

import { EmptyState } from './EmptyState'
import { ErrorState } from './ErrorState'
import { LoadingState } from './LoadingState'
import { analysisService } from '../services/api'
import { ApiError, toApiError } from '../services/apiClient'
import type { AnalysisSummary, Finding, Severity } from '../types/finding'
import { SEVERITIES } from '../types/finding'
import { formatDateTime } from '../utils/format'

/** CWE pages are the canonical description; linking out beats paraphrasing. */
function cweUrl(cweId: string): string {
  return `https://cwe.mitre.org/data/definitions/${cweId.replace('CWE-', '')}.html`
}

interface FindingsPanelProps {
  repositoryId: number
  /** ISO timestamp of the last analysis, or null if it has never run. */
  analyzedAt: string | null
  onAnalyzed: (summary: AnalysisSummary) => void
}

/** One shape for the whole panel, so no two state variables can disagree. */
type FindingsState =
  | { status: 'idle' } // never analysed
  | { status: 'loading' }
  | { status: 'ready'; items: Finding[]; total: number; counts: Record<string, number> }
  | { status: 'error'; error: ApiError }

export function FindingsPanel({ repositoryId, analyzedAt, onAnalyzed }: FindingsPanelProps) {
  // Lazy initialiser: the first render already knows whether there is anything
  // to load, so the effect never has to set state synchronously to correct it.
  const [state, setState] = useState<FindingsState>(() =>
    analyzedAt ? { status: 'loading' } : { status: 'idle' },
  )
  const [severity, setSeverity] = useState<Severity | null>(null)
  const [running, setRunning] = useState(false)
  const [summary, setSummary] = useState<AnalysisSummary | null>(null)
  const [reloads, setReloads] = useState(0)

  useEffect(() => {
    // Nothing to load until the code has been analysed: fetching an empty list
    // would render "no issues found", which is a different claim from "not
    // analysed yet". State is only ever set from the promise callbacks below,
    // never in the effect body.
    if (!analyzedAt) return
    const controller = new AbortController()
    analysisService
      .listFindings(repositoryId, { severity, limit: 100 }, controller.signal)
      .then((page) => {
        if (controller.signal.aborted) return
        setState({
          status: 'ready',
          items: page.items,
          total: page.total,
          counts: page.by_severity,
        })
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted) return
        setState({ status: 'error', error: toApiError(caught) })
      })
    return () => controller.abort()
  }, [repositoryId, analyzedAt, severity, reloads])

  async function runAnalysis() {
    setRunning(true)
    try {
      const result = await analysisService.analyze(repositoryId)
      setSummary(result)
      onAnalyzed(result)
      // The effect above reloads the list once analyzedAt changes; this covers
      // re-analysing, where the timestamp changes but the panel is already open.
      setReloads((value) => value + 1)
    } catch (caught: unknown) {
      setState({ status: 'error', error: toApiError(caught) })
    } finally {
      setRunning(false)
    }
  }

  const counts = state.status === 'ready' ? state.counts : {}
  const totalFindings = Object.values(counts).reduce((sum, value) => sum + value, 0)

  return (
    <div className="findings">
      <div className="findings__header">
        <div>
          <h3 className="findings__title">Security findings</h3>
          <p className="findings__meta">
            {analyzedAt
              ? `Last analysed ${formatDateTime(analyzedAt)}`
              : 'This code has not been analysed yet.'}
          </p>
        </div>
        <button
          type="button"
          className="button button--primary button--small"
          onClick={() => void runAnalysis()}
          disabled={running}
        >
          {running ? 'Analysing…' : analyzedAt ? 'Re-analyse' : 'Analyse code'}
        </button>
      </div>

      {summary && (
        <p className="findings__summary">
          Scanned {summary.files_scanned} file{summary.files_scanned === 1 ? '' : 's'} in{' '}
          {(summary.duration_ms / 1000).toFixed(1)}s
          {summary.unparsable_files > 0 && `, ${summary.unparsable_files} could not be parsed`}
          {summary.truncated && ' — result truncated at the finding limit'}.
        </p>
      )}

      {state.status === 'error' && (
        <ErrorState
          title="Analysis failed"
          message={state.error.message}
          code={state.error.code}
          requestId={state.error.requestId}
        />
      )}

      {totalFindings > 0 && (
        <div className="severity-filters" role="group" aria-label="Filter by severity">
          <button
            type="button"
            className={`chip ${severity === null ? 'chip--active' : ''}`}
            onClick={() => setSeverity(null)}
            aria-pressed={severity === null}
          >
            All {totalFindings}
          </button>
          {SEVERITIES.filter((level) => (counts[level] ?? 0) > 0).map((level) => (
            <button
              key={level}
              type="button"
              className={`chip chip--${level.toLowerCase()} ${
                severity === level ? 'chip--active' : ''
              }`}
              onClick={() => setSeverity(level)}
              aria-pressed={severity === level}
            >
              {level} {counts[level]}
            </button>
          ))}
        </div>
      )}

      {state.status === 'loading' && <LoadingState label="Loading findings…" />}

      {state.status === 'ready' && state.items.length === 0 && (
        <EmptyState
          title={severity ? `No ${severity.toLowerCase()} findings` : 'No issues found'}
          message={
            severity
              ? 'Clear the filter to see the rest.'
              : 'These rules found nothing in this code. That is not a guarantee of security — it means these checks did not match.'
          }
        />
      )}

      {state.status === 'ready' && state.items.length > 0 && (
        <>
          <p className="findings__count">
            Showing {state.items.length} of {state.total}
          </p>
          <ul className="finding-list">
            {state.items.map((finding) => (
              <FindingCard key={finding.id} finding={finding} />
            ))}
          </ul>
        </>
      )}
    </div>
  )
}

function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false)

  return (
    <li className={`finding finding--${finding.severity.toLowerCase()}`}>
      <button
        type="button"
        className="finding__summary"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
      >
        <span className={`severity-tag severity-tag--${finding.severity.toLowerCase()}`}>
          {finding.severity}
        </span>
        <span className="finding__title">{finding.title}</span>
        <span className="finding__location">
          {finding.file_path}:{finding.line_start}
        </span>
      </button>

      {open && (
        <div className="finding__details">
          <p className="finding__message">{finding.message}</p>
          {/* Code from the analysed repository: rendered as text by React, so
              it cannot execute, and already redacted on the server. */}
          <pre className="finding__snippet">
            <code>{finding.snippet}</code>
          </pre>
          <dl className="finding__facts">
            <div>
              <dt>Rule</dt>
              <dd>
                <code>{finding.rule_id}</code>
              </dd>
            </div>
            <div>
              <dt>Confidence</dt>
              <dd>{finding.confidence}</dd>
            </div>
            {finding.cwe_id && (
              <div>
                <dt>Weakness</dt>
                <dd>
                  <a
                    className="link"
                    href={cweUrl(finding.cwe_id)}
                    target="_blank"
                    rel="noreferrer noopener"
                  >
                    {finding.cwe_id}
                  </a>
                </dd>
              </div>
            )}
            {finding.owasp_category && (
              <div>
                <dt>OWASP</dt>
                <dd>{finding.owasp_category}</dd>
              </div>
            )}
          </dl>
        </div>
      )}
    </li>
  )
}
