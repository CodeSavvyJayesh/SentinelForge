import { useEffect, useState } from 'react'

import { ErrorState } from './ErrorState'
import { riskService } from '../services/api'
import { ApiError, toApiError } from '../services/apiClient'
import type { RepositoryRisk, RiskPoint } from '../types/risk'
import { GRADE_LABELS } from '../types/risk'

type State =
  | { status: 'loading' }
  | { status: 'ready'; risk: RepositoryRisk; points: RiskPoint[] }
  | { status: 'error'; error: ApiError }

/**
 * The repository's risk, and how it was arrived at.
 *
 * The grade is what belongs in a summary and the number is for ordering — two
 * digits invite false precision, and a reader who sees 34 and 37 will treat
 * them as meaningfully different when they are not.
 *
 * Expanding shows the arithmetic for each top finding. That is the point of the
 * whole phase: a score nobody can argue with is a score nobody should act on,
 * and "40 base × 0.8 confidence × 0.4 test path" is something a reviewer can
 * disagree with one step at a time.
 */
export function RiskSummary({ repositoryId, reloadKey }: { repositoryId: number; reloadKey: number }) {
  const [state, setState] = useState<State>({ status: 'loading' })
  const [open, setOpen] = useState(false)

  useEffect(() => {
    const controller = new AbortController()
    Promise.all([
      riskService.forRepository(repositoryId, 5, controller.signal),
      riskService.history(repositoryId, 20, controller.signal),
    ])
      .then(([risk, history]) => {
        if (controller.signal.aborted) return
        setState({ status: 'ready', risk, points: history.points })
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted) return
        setState({ status: 'error', error: toApiError(caught) })
      })
    return () => controller.abort()
  }, [repositoryId, reloadKey])

  if (state.status === 'loading') return null

  if (state.status === 'error') {
    return (
      <ErrorState
        title="Could not load the risk score"
        message={state.error.message}
        code={state.error.code}
        requestId={state.error.requestId}
      />
    )
  }

  const { risk, points } = state
  const previous = points.length > 1 ? points[points.length - 2] : undefined
  const change = previous ? risk.score - previous.score : null

  return (
    <section className="risk" aria-label="Repository risk">
      <div className="risk__header">
        <div className={`risk__grade risk__grade--${risk.grade.toLowerCase()}`} aria-hidden="true">
          {risk.grade}
        </div>
        <div className="risk__headline">
          <h3 className="risk__title">
            Risk {risk.score} <span className="risk__of">/ 100</span>
          </h3>
          <p className="risk__label">
            {GRADE_LABELS[risk.grade]} · {risk.finding_count} open finding
            {risk.finding_count === 1 ? '' : 's'}
            {change !== null && change !== 0 && (
              <>
                {' · '}
                <span className={change < 0 ? 'risk__down' : 'risk__up'}>
                  {change < 0 ? '▼' : '▲'} {Math.abs(change).toFixed(1)} since the last scan
                </span>
              </>
            )}
          </p>
        </div>
        <button
          type="button"
          className="button button--small"
          onClick={() => setOpen((value) => !value)}
          aria-expanded={open}
        >
          {open ? 'Hide working' : 'Show working'}
        </button>
      </div>

      {points.length > 1 && <Trend points={points} />}

      {open && (
        <div className="risk__working">
          <p className="risk__note">
            Computed from the findings by a fixed policy (v{risk.policy_version}) — the same
            findings always give the same score. No model is involved.
          </p>
          <ol className="risk__top">
            {risk.top.map((item) => (
              <li key={item.finding_id}>
                <div className="risk__top-head">
                  <span className={`severity-tag severity-tag--${item.severity.toLowerCase()}`}>
                    {item.severity}
                  </span>
                  <span className="risk__top-title">{item.title}</span>
                  <span className="risk__top-score">{item.score}</span>
                </div>
                <p className="risk__sum">
                  <code>{item.explanation}</code>
                </p>
                <ul className="risk__factors">
                  {item.factors.map((factor) => (
                    <li key={factor.name}>
                      <span className="risk__factor-value">×{factor.value}</span> {factor.name} —{' '}
                      {factor.reason}
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ol>
          <p className="risk__note">
            Later findings count for less than earlier ones, so many small issues never outrank one
            severe one. Fixed findings score zero.
          </p>
        </div>
      )}
    </section>
  )
}

/**
 * A bar per scan, oldest on the left.
 *
 * Deliberately not a line chart: with a handful of scans at irregular
 * intervals, a line implies a rate of change between points that the data does
 * not support. Bars say "these are the readings" and nothing more.
 */
function Trend({ points }: { points: RiskPoint[] }) {
  const highest = Math.max(...points.map((point) => point.score), 1)
  return (
    <div className="risk__trend">
      <ol className="risk__bars" aria-hidden="true">
        {points.map((point) => (
          <li key={point.scan_id} style={{ height: `${Math.max(4, (point.score / highest) * 100)}%` }} />
        ))}
      </ol>
      <p className="risk__trend-label">
        Last {points.length} scans, oldest first
      </p>
    </div>
  )
}
