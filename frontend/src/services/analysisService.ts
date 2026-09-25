import type { ApiClient } from './apiClient'
import type { AnalysisSummary, FindingListResponse, Severity } from '../types/finding'

export const REPOSITORIES_PATH = '/api/v1/repositories'

/** Parsing a whole repository takes longer than an ordinary request. */
export const ANALYSIS_TIMEOUT_MS = 180_000

export interface FindingQuery {
  severity?: Severity | null
  limit?: number
  offset?: number
}

export interface AnalysisService {
  analyze(repositoryId: number): Promise<AnalysisSummary>
  listFindings(
    repositoryId: number,
    query?: FindingQuery,
    signal?: AbortSignal,
  ): Promise<FindingListResponse>
}

function buildQuery({ severity, limit = 50, offset = 0 }: FindingQuery = {}): string {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) })
  // Only sent when a severity is actually chosen: an empty value would filter
  // on "" and return nothing.
  if (severity) params.set('severity', severity)
  return params.toString()
}

export function createAnalysisService(client: ApiClient): AnalysisService {
  return {
    async analyze(repositoryId) {
      const result = await client.request<AnalysisSummary>(
        `${REPOSITORIES_PATH}/${repositoryId}/analyze`,
        { method: 'POST', auth: true, timeoutMs: ANALYSIS_TIMEOUT_MS },
      )
      return result.data
    },

    async listFindings(repositoryId, query, signal) {
      const result = await client.request<FindingListResponse>(
        `${REPOSITORIES_PATH}/${repositoryId}/findings?${buildQuery(query)}`,
        { auth: true, signal },
      )
      return result.data
    },
  }
}
