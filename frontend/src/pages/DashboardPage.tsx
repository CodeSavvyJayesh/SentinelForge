import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

import { EmptyState } from '../components/EmptyState'
import { ErrorState } from '../components/ErrorState'
import { LoadingState } from '../components/LoadingState'
import { dashboardService } from '../services/api'
import { ApiError, toApiError } from '../services/apiClient'
import type {
  BarRow,
  Dashboard,
  DashboardFinding,
  DashboardFixes,
  DashboardRepository,
  DashboardTrendPoint,
} from '../types/dashboard'
import {
  fixRows,
  passRate,
  repositoryLabel,
  severityRows,
  weaknessRows,
} from '../types/dashboard'
import { GRADE_LABELS } from '../types/risk'
import { EMPTY_VALUE, formatDateTime } from '../utils/format'

type State =
  | { status: 'loading' }
  | { status: 'ready'; data: Dashboard; refreshing: boolean }
  | { status: 'error'; error: ApiError }

/**
 * Everything the signed-in user has scanned, on one page.
 *
 * Every figure is counted by the API from rows the earlier phases wrote. There
 * is no sample data and nothing is filled in to make an empty account look
 * busy: with nothing scanned the page says so and links to where to start.
 *
 * The charts are bar lists in one colour with the number written beside every
 * bar. Severity already has a colour scale elsewhere in the app, but two of
 * its steps are hard to tell apart side by side and pass/reject in red and
 * green is unreadable to a colour-blind reader — so here the label carries the
 * identity and the bar carries only the size.
 */
export function DashboardPage() {
  const [state, setState] = useState<State>({ status: 'loading' })
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    dashboardService
      .load(controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) setState({ status: 'ready', data, refreshing: false })
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted) return
        setState({ status: 'error', error: toApiError(caught) })
      })
    return () => controller.abort()
  }, [attempt])

  const reload = useCallback(() => {
    // Keep what is on screen while re-fetching: a spinner replacing the whole
    // page for a refresh that changes two numbers is a layout jump for nothing.
    setState((current) =>
      current.status === 'ready' ? { ...current, refreshing: true } : { status: 'loading' },
    )
    setAttempt((value) => value + 1)
  }, [])

  return (
    <section className="page" aria-labelledby="dashboard-title">
      <div className="page__header">
        <div>
          <h1 id="dashboard-title">Dashboard</h1>
          <p className="page__subtitle">
            {state.status === 'ready'
              ? `Everything you have scanned, as of ${formatDateTime(state.data.generated_at)}.`
              : 'Everything you have scanned, across all your projects.'}
          </p>
        </div>
        <button
          type="button"
          className="button"
          onClick={reload}
          disabled={state.status === 'loading' || (state.status === 'ready' && state.refreshing)}
        >
          Refresh
        </button>
      </div>

      {state.status === 'loading' && <LoadingState label="Loading the dashboard…" />}

      {state.status === 'error' && (
        <ErrorState
          title="Could not load the dashboard"
          message={state.error.message}
          code={state.error.code}
          requestId={state.error.requestId}
          onRetry={reload}
        />
      )}

      {state.status === 'ready' && (
        <div className={state.refreshing ? 'dashboard dashboard--refreshing' : 'dashboard'}>
          <Overview data={state.data} />
        </div>
      )}
    </section>
  )
}

function Overview({ data }: { data: Dashboard }) {
  const { totals } = data

  if (totals.projects === 0) {
    return (
      <EmptyState
        title="Nothing to show yet"
        message="Create a project, connect its code and run a scan. The dashboard fills in from real scans only."
        action={
          <Link className="button button--primary" to="/projects/new">
            Create project
          </Link>
        }
      />
    )
  }

  const unscanned = totals.repositories - totals.repositories_scanned

  return (
    <>
      <dl className="tiles">
        <Tile
          hero
          label="Open findings"
          value={totals.open_findings}
          note={
            totals.repositories_scanned === 0
              ? 'No scan has completed yet'
              : `across ${count(totals.repositories_scanned, 'scanned repository', 'scanned repositories')}`
          }
        />
        <Tile label="Fixed findings" value={totals.fixed_findings} note="gone in a later scan" />
        <Tile
          label="Repositories"
          value={totals.repositories}
          note={
            unscanned === 0
              ? 'all scanned'
              : `${unscanned} not scanned yet`
          }
        />
        <Tile label="Completed scans" value={totals.scans_completed} note="all time" />
        <Tile label="Projects" value={totals.projects} note="only you can see them" />
      </dl>

      <div className="dashboard__columns">
        <section className="panel dashboard__panel" aria-labelledby="dash-severity">
          <h2 id="dash-severity" className="dashboard__heading">
            Open findings by severity
          </h2>
          {totals.open_findings === 0 ? (
            <p className="dashboard__empty">
              {totals.repositories_scanned === 0
                ? 'Nothing has been scanned yet.'
                : 'No open findings in anything you have scanned.'}
            </p>
          ) : (
            <BarList rows={severityRows(data.open_by_severity)} unit="open findings" />
          )}
        </section>

        <section className="panel dashboard__panel" aria-labelledby="dash-weaknesses">
          <h2 id="dash-weaknesses" className="dashboard__heading">
            Most common weaknesses
          </h2>
          {data.weaknesses.length === 0 ? (
            <p className="dashboard__empty">No open findings to group.</p>
          ) : (
            <BarList rows={weaknessRows(data.weaknesses)} unit="open findings" stacked />
          )}
        </section>
      </div>

      <section className="panel dashboard__panel" aria-labelledby="dash-repositories">
        <h2 id="dash-repositories" className="dashboard__heading">
          Repositories, highest risk first
        </h2>
        {data.repositories.length === 0 ? (
          <p className="dashboard__empty">
            No code is connected yet. Open a project and upload an archive or clone a repository.
          </p>
        ) : (
          <Repositories items={data.repositories} policyVersion={data.policy_version} />
        )}
      </section>

      <section className="panel dashboard__panel" aria-labelledby="dash-top">
        <h2 id="dash-top" className="dashboard__heading">
          Highest-risk findings
        </h2>
        {data.top_findings.length === 0 ? (
          <p className="dashboard__empty">No open findings.</p>
        ) : (
          <ol className="dash-findings">
            {data.top_findings.map((item) => (
              <TopFinding key={item.finding_id} item={item} />
            ))}
          </ol>
        )}
      </section>

      <section className="panel dashboard__panel" aria-labelledby="dash-fixes">
        <h2 id="dash-fixes" className="dashboard__heading">
          Proposed fixes
        </h2>
        <Fixes fixes={data.fixes} />
      </section>
    </>
  )
}

function count(value: number, singular: string, plural: string): string {
  return `${value} ${value === 1 ? singular : plural}`
}

function Tile({
  label,
  value,
  note,
  hero = false,
}: {
  label: string
  value: number
  note: string
  hero?: boolean
}) {
  return (
    <div className={hero ? 'tile tile--hero' : 'tile'}>
      <dt className="tile__label">{label}</dt>
      <dd className="tile__value">{value.toLocaleString()}</dd>
      <dd className="tile__note">{note}</dd>
    </div>
  )
}

/**
 * A label, a bar and the number, per row.
 *
 * The number is always printed, so nothing depends on hovering; the title is
 * the same fact as a sentence. The list is its own table view.
 */
function BarList({
  rows,
  unit,
  stacked = false,
}: {
  rows: BarRow[]
  unit: string
  /** Put each label on its own line: for labels too long to sit beside a bar. */
  stacked?: boolean
}) {
  return (
    <ul className={stacked ? 'bar-list bar-list--stacked' : 'bar-list'} aria-label={`Counts of ${unit}`}>
      {rows.map((row) => (
        <li key={row.key} className="bar-list__row" title={row.description}>
          <span className="bar-list__label">{row.label}</span>
          <span className="bar-list__track" aria-hidden="true">
            <span className="bar-list__bar" style={{ width: `${row.percent}%` }} />
          </span>
          <span className="bar-list__value">{row.value.toLocaleString()}</span>
          <span className="visually-hidden">{row.description}</span>
        </li>
      ))}
    </ul>
  )
}

function Repositories({
  items,
  policyVersion,
}: {
  items: DashboardRepository[]
  policyVersion: number
}) {
  return (
    <>
      <div className="dash-table__scroll">
        <table className="scan-table dash-table">
          <thead>
            <tr>
              <th scope="col">Repository</th>
              <th scope="col">Risk</th>
              <th scope="col" className="dash-table__number">
                Open
              </th>
              <th scope="col" className="dash-table__number">
                Fixed
              </th>
              <th scope="col">Risk per scan</th>
              <th scope="col">Last scan</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.repository_id}>
                <th scope="row" className="dash-table__name">
                  <Link to={`/projects/${item.project_id}`}>{repositoryLabel(item.origin)}</Link>
                  <span className="dash-table__project">
                    {item.project_name}
                    {item.primary_language ? ` · ${item.primary_language}` : ''}
                  </span>
                </th>
                <td>
                  {item.score === null || item.grade === null ? (
                    <span className="dash-table__muted">Not scanned</span>
                  ) : (
                    <span className="dash-grade" title={GRADE_LABELS[item.grade]}>
                      <span className={`dash-grade__letter risk__grade--${item.grade.toLowerCase()}`}>
                        {item.grade}
                      </span>
                      <span className="dash-grade__score">{item.score}</span>
                      <span className="visually-hidden">{GRADE_LABELS[item.grade]}</span>
                    </span>
                  )}
                </td>
                <td className="dash-table__number">
                  {item.score === null ? EMPTY_VALUE : item.open_findings}
                </td>
                <td className="dash-table__number">
                  {item.score === null ? EMPTY_VALUE : item.fixed_findings}
                </td>
                <td>
                  <Spark points={item.trend} />
                </td>
                <td>{formatDateTime(item.last_scan_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="dashboard__note">
        Risk is 0–100, from a fixed scoring policy (v{policyVersion}) — no model is involved. The
        current score is computed now; the bars are what each scan recorded when it ran, oldest on
        the left, all on the same 0–100 scale.
      </p>
    </>
  )
}

/**
 * One bar per scan, oldest on the left, on a fixed 0–100 scale.
 *
 * Fixed rather than stretched to the tallest bar, so two repositories in the
 * same table can be compared: a row of short bars really is lower risk than a
 * row of tall ones. Bars rather than a line for the same reason as on the
 * repository page — a few scans at irregular intervals are readings, not a rate.
 */
function Spark({ points }: { points: DashboardTrendPoint[] }) {
  if (points.length === 0) return <span className="dash-table__muted">{EMPTY_VALUE}</span>
  const first = points[0]
  const last = points[points.length - 1]
  const summary =
    points.length === 1 || !first || !last
      ? `One scan, risk ${last?.score ?? 0}`
      : `${points.length} scans, risk ${first.score} then ${last.score}`
  return (
    <span className="spark" role="img" aria-label={summary}>
      {points.map((point) => (
        <span
          key={point.scan_id}
          className="spark__slot"
          title={`${formatDateTime(point.finished_at)} — risk ${point.score} (${point.grade}), ${point.total_findings} findings`}
        >
          <span className="spark__bar" style={{ height: `${Math.max(6, Math.min(100, point.score))}%` }} />
        </span>
      ))}
    </span>
  )
}

function TopFinding({ item }: { item: DashboardFinding }) {
  return (
    <li className="dash-finding">
      <div className="dash-finding__head">
        <span className={`severity-tag severity-tag--${item.severity.toLowerCase()}`}>
          {item.severity}
        </span>
        <Link className="dash-finding__title" to={`/projects/${item.project_id}`}>
          {item.title}
        </Link>
        <span className="dash-finding__score" title={item.explanation}>
          {item.score}
        </span>
      </div>
      <p className="dash-finding__where">
        <code>
          {item.file_path}:{item.line_start}
        </code>{' '}
        · {item.project_name} · {repositoryLabel(item.origin)}
        {item.cwe_id ? ` · ${item.cwe_id}` : ''}
      </p>
      <p className="dash-finding__sum">
        <code>{item.explanation}</code>
      </p>
    </li>
  )
}

function Fixes({ fixes }: { fixes: DashboardFixes }) {
  if (fixes.requested === 0) {
    return (
      <p className="dashboard__empty">
        No fix has been requested yet. Open a finding and choose “Suggest a fix”.
      </p>
    )
  }
  const rate = passRate(fixes)
  return (
    <>
      <p className="dashboard__lede">
        {count(fixes.requested, 'fix was requested', 'fixes were requested')}.{' '}
        {rate === null
          ? 'None has a verdict from a re-scan yet.'
          : `Of the ${fixes.labelled} that a re-scan could judge, ${fixes.passed} passed (${rate}%).`}
      </p>
      <BarList rows={fixRows(fixes)} unit="requested fixes" stacked />
      <p className="dashboard__note">
        A fix that passed has still changed nothing: it was applied to a throwaway copy and
        re-scanned, and the finding stays open until your own code is scanned without it.{' '}
        <strong>{fixes.labelled}</strong> {fixes.labelled === 1 ? 'proposal has' : 'proposals have'} a
        verdict (passed or rejected) — those are the examples a patch-outcome classifier can be
        trained on. Checks that could not run are not counted, because they say nothing about the
        change.
      </p>
    </>
  )
}
