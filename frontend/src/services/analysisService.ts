import type { ApiClient } from './apiClient'
import type { FindingListResponse, FindingStatus, Severity } from '../types/finding'

export const REPOSITORIES_PATH = '/api/v1/repositories'

export interface FindingQuery {
  severity?: Severity | null
  status?: FindingStatus | null
  limit?: number
  offset?: number
}

export interface AnalysisService {
  listFindings(
    repositoryId: number,
    query?: FindingQuery,
    signal?: AbortSignal,
  ): Promise<FindingListResponse>
}

function buildQuery({ severity, status, limit = 50, offset = 0 }: FindingQuery = {}): string {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) })
  // Only sent when a filter is actually chosen: an empty value would filter on
  // "" and return nothing.
  if (severity) params.set('severity', severity)
  if (status) params.set('finding_status', status)
  return params.toString()
}

export function createAnalysisService(client: ApiClient): AnalysisService {
  return {
    async listFindings(repositoryId, query, signal) {
      const result = await client.request<FindingListResponse>(
        `${REPOSITORIES_PATH}/${repositoryId}/findings?${buildQuery(query)}`,
        { auth: true, signal },
      )
      return result.data
    },
  }
}
