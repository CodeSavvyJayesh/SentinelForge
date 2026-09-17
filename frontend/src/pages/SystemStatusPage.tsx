import { ErrorState } from '../components/ErrorState'
import { LoadingState } from '../components/LoadingState'
import { StatusBadge } from '../components/StatusBadge'
import { appConfig } from '../config/env'
import { useHealth } from '../hooks/useHealth'
import type { ApiResult } from '../types/api'
import type { HealthResponse } from '../types/health'
import { EMPTY_VALUE, formatDateTime, formatLatency } from '../utils/format'

export function SystemStatusPage() {
  const { state, refresh } = useHealth()

  return (
    <section aria-labelledby="page-title" className="page">
      <div className="page__header">
        <div>
          <h1 id="page-title">System status</h1>
          <p className="page__subtitle">
            Live readiness of the SentinelForge API and the services it depends on.
          </p>
        </div>
        <button
          type="button"
          className="button"
          onClick={refresh}
          disabled={state.status === 'loading'}
        >
          {state.status === 'loading' ? 'Checking…' : 'Refresh'}
        </button>
      </div>

      {state.status === 'loading' && <LoadingState label="Checking backend health…" />}

      {state.status === 'error' && (
        <ErrorState
          title="API unavailable"
          message={state.error.message}
          code={state.error.code}
          requestId={state.error.requestId}
          onRetry={refresh}
        />
      )}

      {state.status === 'success' && <HealthReport result={state.result} />}
    </section>
  )
}

function HealthReport({ result }: { result: ApiResult<HealthResponse> }) {
  const report = result.data
  const database = report.checks.database
  const healthy = report.status === 'healthy'

  return (
    <div className="panel">
      <div className={`panel__summary ${healthy ? 'panel__summary--ok' : 'panel__summary--fail'}`}>
        <StatusBadge tone={healthy ? 'ok' : 'fail'} label={healthy ? 'Healthy' : 'Unhealthy'} />
        <p>
          {healthy
            ? 'All checked services are operational.'
            : 'One or more services are unavailable. Scans cannot run until this is resolved.'}
        </p>
      </div>

      <table className="checks">
        <caption className="visually-hidden">Service checks</caption>
        <thead>
          <tr>
            <th scope="col">Service</th>
            <th scope="col">Status</th>
            <th scope="col">Latency</th>
            <th scope="col">Details</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <th scope="row">API server</th>
            <td>
              <StatusBadge tone="ok" label="Reachable" />
            </td>
            <td>{EMPTY_VALUE}</td>
            <td>
              Version <code>{report.version}</code>
            </td>
          </tr>
          <tr>
            <th scope="row">PostgreSQL</th>
            <td>
              <StatusBadge
                tone={database.status === 'up' ? 'ok' : 'fail'}
                label={database.status === 'up' ? 'Up' : 'Down'}
              />
            </td>
            <td>{formatLatency(database.latency_ms)}</td>
            <td>{database.message ?? EMPTY_VALUE}</td>
          </tr>
        </tbody>
      </table>

      <dl className="meta-list meta-list--footer">
        <div>
          <dt>Checked at</dt>
          <dd>{formatDateTime(report.checked_at)}</dd>
        </div>
        <div>
          <dt>Request ID</dt>
          <dd>
            <code>{result.requestId ?? EMPTY_VALUE}</code>
          </dd>
        </div>
        <div>
          <dt>API base URL</dt>
          <dd>
            <code>{appConfig.apiBaseUrl ?? EMPTY_VALUE}</code>
          </dd>
        </div>
      </dl>
    </div>
  )
}
