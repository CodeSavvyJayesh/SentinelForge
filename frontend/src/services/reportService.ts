import type { ApiClient } from './apiClient'
import type { ReportExport, ReportFormat } from '../types/report'

export const REPOSITORIES_PATH = '/api/v1/repositories'

/** Rendering a few hundred findings is quick, but not instant. */
export const REPORT_TIMEOUT_MS = 30_000

export interface ReportService {
  /** The repository's report, rendered in one format. Every call is recorded by the API. */
  export(repositoryId: number, format: ReportFormat, signal?: AbortSignal): Promise<ReportExport>
}

export function createReportService(client: ApiClient): ReportService {
  return {
    async export(repositoryId, format, signal) {
      const result = await client.request<ReportExport>(
        `${REPOSITORIES_PATH}/${repositoryId}/report/export?format=${encodeURIComponent(format)}`,
        { auth: true, signal, timeoutMs: REPORT_TIMEOUT_MS },
      )
      return result.data
    },
  }
}
