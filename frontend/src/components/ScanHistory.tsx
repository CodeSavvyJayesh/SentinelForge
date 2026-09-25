import { useEffect, useState } from 'react'

import { scanService } from '../services/api'
import { toApiError } from '../services/apiClient'
import type { Scan } from '../types/scan'
import { formatDateTime } from '../utils/format'

/** Scans are history: each row keeps the numbers it found, not today's. */
export function ScanHistory({
  repositoryId,
  reloadKey,
}: {
  repositoryId: number
  /** Bumped by the panel when a scan finishes, to refetch the list. */
  reloadKey: number
}) {
  const [scans, setScans] = useState<Scan[] | null>(null)
  const [open, setOpen] = useState(false)

  useEffect(() => {
    const controller = new AbortController()
    scanService
      .listForRepository(repositoryId, 10, controller.signal)
      .then((page) => {
        if (!controller.signal.aborted) setScans(page.items)
      })
      .catch((caught: unknown) => {
        if (!controller.signal.aborted) {
          toApiError(caught) // history is secondary: a failure here is not an alert
          setScans([])
        }
      })
    return () => controller.abort()
  }, [repositoryId, reloadKey])

  if (!scans || scans.length === 0) return null

  return (
    <div className="scan-history">
      <button
        type="button"
        className="scan-history__toggle"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
      >
        Scan history ({scans.length})
      </button>

      {open && (
        <table className="scan-table">
          <thead>
            <tr>
              <th scope="col">When</th>
              <th scope="col">Status</th>
              <th scope="col">Findings</th>
              <th scope="col">New</th>
              <th scope="col">Fixed</th>
              <th scope="col">Took</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => (
              <tr key={scan.id}>
                <td>{formatDateTime(scan.created_at)}</td>
                <td>
                  <span className={`state-tag state-tag--scan-${scan.status.toLowerCase()}`}>
                    {scan.status}
                  </span>
                  {scan.status === 'FAILED' && scan.error_message && (
                    <span className="scan-table__error"> {scan.error_message}</span>
                  )}
                </td>
                <td>{scan.status === 'COMPLETED' ? scan.total_findings : '—'}</td>
                <td>{scan.status === 'COMPLETED' ? scan.new_findings : '—'}</td>
                <td>{scan.status === 'COMPLETED' ? scan.fixed_findings : '—'}</td>
                <td>{scan.duration_ms === null ? '—' : `${(scan.duration_ms / 1000).toFixed(1)}s`}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
