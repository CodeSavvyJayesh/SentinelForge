import { useCallback, useEffect, useState } from 'react'

import { ErrorState } from '../components/ErrorState'
import { LoadingState } from '../components/LoadingState'
import { ApiError, toApiError } from '../services/apiClient'
import { userService } from '../services/api'
import type { UserListResponse } from '../types/auth'
import { formatDateTime } from '../utils/format'

type PanelState =
  | { status: 'loading' }
  | { status: 'success'; data: UserListResponse }
  | { status: 'error'; error: ApiError }

/** Admin-only list of accounts; proves role-based access control end to end. */
export function UsersPanel() {
  const [state, setState] = useState<PanelState>({ status: 'loading' })
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let active = true
    userService
      .list()
      .then((data) => {
        if (active) setState({ status: 'success', data })
      })
      .catch((caught: unknown) => {
        if (active) setState({ status: 'error', error: toApiError(caught) })
      })
    return () => {
      active = false
    }
  }, [attempt])

  const retry = useCallback(() => {
    setState({ status: 'loading' })
    setAttempt((value) => value + 1)
  }, [])

  if (state.status === 'loading') return <LoadingState label="Loading accounts…" />
  if (state.status === 'error') {
    return (
      <ErrorState
        title="Could not load accounts"
        message={state.error.message}
        code={state.error.code}
        requestId={state.error.requestId}
        onRetry={retry}
      />
    )
  }

  return (
    <div className="panel">
      <div className="panel__summary">
        <h2 className="panel__title">Accounts</h2>
        <p>{state.data.total} registered</p>
      </div>
      <table className="checks">
        <caption className="visually-hidden">Registered accounts</caption>
        <thead>
          <tr>
            <th scope="col">Username</th>
            <th scope="col">Email</th>
            <th scope="col">Role</th>
            <th scope="col">Status</th>
            <th scope="col">Created</th>
          </tr>
        </thead>
        <tbody>
          {state.data.items.map((user) => (
            <tr key={user.id}>
              <th scope="row">{user.username}</th>
              <td>{user.email}</td>
              <td>
                <span className={`role-tag role-tag--${user.role.toLowerCase()}`}>{user.role}</span>
              </td>
              <td>{user.is_active ? 'Active' : 'Disabled'}</td>
              <td>{formatDateTime(user.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
