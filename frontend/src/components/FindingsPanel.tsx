import { useEffect, useState } from 'react'

import { EmptyState } from './EmptyState'
import { ErrorState } from './ErrorState'
import { LoadingState } from './LoadingState'
import { ScanHistory } from './ScanHistory'
import { analysisService, scanService } from '../services/api'
import { SCAN_POLL_INTERVAL_MS } from '../services/scanService'
import { ApiError, toApiError } from '../services/apiClient'
import type { Finding, FindingStatus, Severity } from '../types/finding'
import { SEVERITIES } from '../types/finding'
import type { Scan } from '../types/scan'
import { ACTIVE_SCAN_STATUSES } from '../types/scan'
import { formatDateTime } from '../utils/format'

/** CWE pages are the canonical description; linking out beats paraphrasing. */
function cweUrl(cweId: string): string {
  return `https://cwe.mitre.org/data/definitions/${cweId.replace('CWE-', '')}.html`
}

const STATUS_LABELS: Record<FindingStatus, string> = {
  NEW: 'New',
  OPEN: 'Open',
  FIXED: 'Fixed',
}

/** One shape for the whole list, so no two state variables can disagree. */
type FindingsState =
  | { status: 'idle' } // never scanned
  | { status: 'loading' }
  | {
      status: 'ready'
      items: Finding[]
      total: number
      bySeverity: Record<string, number>
      byStatus: Record<string, number>
    }
  | { status: 'error'; error: ApiError }

interface FindingsPanelProps {
  repositoryId: number
  /** ISO timestamp of the last scan, or null if it has never run. */
  analyzedAt: string | null
  onScanned: (scan: Scan) => void
}

export function FindingsPanel({ repositoryId, analyzedAt, onScanned }: FindingsPanelProps) {
  const [state, setState] = useState<FindingsState>(() =>
    analyzedAt ? { status: 'loading' } : { status: 'idle' },
  )
  const [severity, setSeverity] = useState<Severity | null>(null)
  const [findingStatus, setFindingStatus] = useState<FindingStatus | null>(null)
  const [activeScan, setActiveScan] = useState<Scan | null>(null)
  const [queueError, setQueueError] = useState<ApiError | null>(null)
  const [reloads, setReloads] = useState(0)

  // Load findings whenever the filters change or a scan finishes.
  useEffect(() => {
    if (!analyzedAt) return
    const controller = new AbortController()
    analysisService
      .listFindings(repositoryId, { severity, status: findingStatus, limit: 100 }, controller.signal)
      .then((page) => {
        if (controller.signal.aborted) return
        setState({
          status: 'ready',
          items: page.items,
          total: page.total,
          bySeverity: page.by_severity,
          byStatus: page.by_status,
        })
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted) return
        setState({ status: 'error', error: toApiError(caught) })
      })
    return () => controller.abort()
  }, [repositoryId, analyzedAt, severity, findingStatus, reloads])

  // While a scan is queued or running, ask the API how it is getting on. The
  // worker is a separate process: the only way to know is to look.
  useEffect(() => {
    if (!activeScan || !ACTIVE_SCAN_STATUSES.includes(activeScan.status)) return
    let cancelled = false
    const timer = setTimeout(() => {
      scanService
        .get(activeScan.id)
        .then((scan) => {
          if (cancelled) return
          setActiveScan(scan)
          if (!ACTIVE_SCAN_STATUSES.includes(scan.status)) {
            onScanned(scan)
            setReloads((value) => value + 1)
          }
        })
        .catch(() => {
          // A failed poll is not a failed scan; the next tick tries again.
        })
    }, SCAN_POLL_INTERVAL_MS)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [activeScan, onScanned])

  async function startScan() {
    setQueueError(null)
    try {
      setActiveScan(await scanService.queue(repositoryId))
    } catch (caught: unknown) {
      setQueueError(toApiError(caught))
    }
  }

  const scanning = activeScan !== null && ACTIVE_SCAN_STATUSES.includes(activeScan.status)
  const bySeverity = state.status === 'ready' ? state.bySeverity : {}
  const byStatus = state.status === 'ready' ? state.byStatus : {}
  const totalOpen = Object.values(bySeverity).reduce((sum, value) => sum + value, 0)

  return (
    <div className="findings">
      <div className="findings__header">
        <div>
          <h3 className="findings__title">Security findings</h3>
          <p className="findings__meta">
            {analyzedAt
              ? `Last scanned ${formatDateTime(analyzedAt)}`
              : 'This code has not been scanned yet.'}
          </p>
        </div>
        <button
          type="button"
          className="button button--primary button--small"
          onClick={() => void startScan()}
          disabled={scanning}
        >
          {scanning
            ? activeScan?.status === 'QUEUED'
              ? 'Queued…'
              : 'Scanning…'
            : analyzedAt
              ? 'Scan again'
              : 'Scan code'}
        </button>
      </div>

      {scanning && (
        <p className="findings__summary" role="status">
          {activeScan?.status === 'QUEUED'
            ? 'Waiting for a worker to pick this up…'
            : 'The worker is analysing your code…'}
        </p>
      )}

      {activeScan?.status === 'COMPLETED' && (
        <p className="findings__summary">
          Scanned {activeScan.files_scanned} file{activeScan.files_scanned === 1 ? '' : 's'} in{' '}
          {((activeScan.duration_ms ?? 0) / 1000).toFixed(1)}s —{' '}
          <strong>{activeScan.new_findings} new</strong>, {activeScan.fixed_findings} fixed
          {activeScan.truncated && ' (result truncated at the finding limit)'}.
        </p>
      )}

      {activeScan?.status === 'FAILED' && (
        <ErrorState
          title="The scan failed"
          message={activeScan.error_message ?? 'The scan did not finish.'}
        />
      )}

      {queueError && (
        <ErrorState
          title="Could not start a scan"
          message={queueError.message}
          code={queueError.code}
          requestId={queueError.requestId}
        />
      )}

      {state.status === 'error' && (
        <ErrorState
          title="Could not load findings"
          message={state.error.message}
          code={state.error.code}
          requestId={state.error.requestId}
        />
      )}

      {state.status === 'ready' && (byStatus.NEW ?? 0) + (byStatus.OPEN ?? 0) + (byStatus.FIXED ?? 0) > 0 && (
        <>
          <div className="severity-filters" role="group" aria-label="Filter by state">
            <button
              type="button"
              className={`chip ${findingStatus === null ? 'chip--active' : ''}`}
              onClick={() => setFindingStatus(null)}
              aria-pressed={findingStatus === null}
            >
              All states
            </button>
            {(['NEW', 'OPEN', 'FIXED'] as FindingStatus[])
              .filter((value) => (byStatus[value] ?? 0) > 0)
              .map((value) => (
                <button
                  key={value}
                  type="button"
                  className={`chip chip--status-${value.toLowerCase()} ${
                    findingStatus === value ? 'chip--active' : ''
                  }`}
                  onClick={() => setFindingStatus(value)}
                  aria-pressed={findingStatus === value}
                >
                  {STATUS_LABELS[value]} {byStatus[value]}
                </button>
              ))}
          </div>

          <div className="severity-filters" role="group" aria-label="Filter by severity">
            <button
              type="button"
              className={`chip ${severity === null ? 'chip--active' : ''}`}
              onClick={() => setSeverity(null)}
              aria-pressed={severity === null}
            >
              All severities {totalOpen}
            </button>
            {SEVERITIES.filter((level) => (bySeverity[level] ?? 0) > 0).map((level) => (
              <button
                key={level}
                type="button"
                className={`chip chip--${level.toLowerCase()} ${
                  severity === level ? 'chip--active' : ''
                }`}
                onClick={() => setSeverity(level)}
                aria-pressed={severity === level}
              >
                {level} {bySeverity[level]}
              </button>
            ))}
          </div>
        </>
      )}

      {state.status === 'loading' && <LoadingState label="Loading findings…" />}

      {state.status === 'ready' && state.items.length === 0 && (
        <EmptyState
          title={severity || findingStatus ? 'Nothing matches that filter' : 'No issues found'}
          message={
            severity || findingStatus
              ? 'Clear the filters to see the rest.'
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

      <ScanHistory repositoryId={repositoryId} reloadKey={reloads} />
    </div>
  )
}

function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false)
  const fixed = finding.status === 'FIXED'

  return (
    <li className={`finding finding--${finding.severity.toLowerCase()} ${fixed ? 'finding--fixed' : ''}`}>
      <button
        type="button"
        className="finding__summary"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
      >
        <span className={`severity-tag severity-tag--${finding.severity.toLowerCase()}`}>
          {finding.severity}
        </span>
        {finding.status !== 'OPEN' && (
          <span className={`state-tag state-tag--${finding.status.toLowerCase()}`}>
            {STATUS_LABELS[finding.status]}
          </span>
        )}
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
            <div>
              <dt>State</dt>
              <dd>
                {STATUS_LABELS[finding.status]}
                {fixed && finding.fixed_in_scan_id && ` in scan #${finding.fixed_in_scan_id}`}
              </dd>
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
