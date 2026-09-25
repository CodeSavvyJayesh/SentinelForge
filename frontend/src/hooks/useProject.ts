import { useCallback, useEffect, useState } from 'react'

import { projectService } from '../services/api'
import { ApiError, toApiError } from '../services/apiClient'
import type { Project } from '../types/project'

export type ProjectState =
  | { status: 'loading' }
  | { status: 'success'; project: Project }
  | { status: 'error'; error: ApiError }

/** Loads one project. A project owned by someone else simply comes back 404. */
export function useProject(projectId: number) {
  const [state, setState] = useState<ProjectState>({ status: 'loading' })
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    projectService
      .get(projectId, controller.signal)
      .then((project) => {
        if (!controller.signal.aborted) setState({ status: 'success', project })
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted) return
        setState({ status: 'error', error: toApiError(caught) })
      })
    return () => controller.abort()
  }, [projectId, attempt])

  const reload = useCallback(() => {
    setState({ status: 'loading' })
    setAttempt((value) => value + 1)
  }, [])

  const setProject = useCallback((project: Project) => {
    setState({ status: 'success', project })
  }, [])

  return { state, reload, setProject }
}
