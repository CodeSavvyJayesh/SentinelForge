import { useCallback, useEffect, useState } from 'react'

import { projectService } from '../services/api'
import { ApiError, toApiError } from '../services/apiClient'
import type { ProjectListResponse, ProjectQuery } from '../types/project'

export type ProjectsState =
  | { status: 'loading' }
  | { status: 'success'; data: ProjectListResponse }
  | { status: 'error'; error: ApiError }

/** Loads the signed-in user's projects; `reload()` re-fetches after changes. */
export function useProjects(query: ProjectQuery = {}) {
  const { search, limit = 20, offset = 0 } = query
  const [state, setState] = useState<ProjectsState>({ status: 'loading' })
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    projectService
      .list({ search, limit, offset }, controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) setState({ status: 'success', data })
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted) return
        setState({ status: 'error', error: toApiError(caught) })
      })
    return () => controller.abort()
  }, [search, limit, offset, attempt])

  const reload = useCallback(() => {
    setState({ status: 'loading' })
    setAttempt((value) => value + 1)
  }, [])

  return { state, reload }
}
