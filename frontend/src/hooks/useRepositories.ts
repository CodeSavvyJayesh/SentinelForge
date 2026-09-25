import { useCallback, useEffect, useState } from 'react'

import { repositoryService } from '../services/api'
import { ApiError, toApiError } from '../services/apiClient'
import type { Repository } from '../types/repository'

export type RepositoriesState =
  | { status: 'loading' }
  | { status: 'success'; items: Repository[] }
  | { status: 'error'; error: ApiError }

/** Loads the repositories connected to one project. */
export function useRepositories(projectId: number) {
  const [state, setState] = useState<RepositoriesState>({ status: 'loading' })
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    repositoryService
      .listForProject(projectId, controller.signal)
      .then((response) => {
        if (!controller.signal.aborted) setState({ status: 'success', items: response.items })
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

  /** Put a newly ingested repository at the top without a round trip. */
  const prepend = useCallback((repository: Repository) => {
    setState((current) =>
      current.status === 'success'
        ? { status: 'success', items: [repository, ...current.items] }
        : { status: 'success', items: [repository] },
    )
  }, [])

  const drop = useCallback((repositoryId: number) => {
    setState((current) =>
      current.status === 'success'
        ? { status: 'success', items: current.items.filter((item) => item.id !== repositoryId) }
        : current,
    )
  }, [])

  return { state, reload, prepend, drop }
}
