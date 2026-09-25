import type { ApiClient } from './apiClient'
import type { Scan, ScanListResponse } from '../types/scan'

export const REPOSITORIES_PATH = '/api/v1/repositories'
export const SCANS_PATH = '/api/v1/scans'

/** How often the UI asks whether a running scan has finished. */
export const SCAN_POLL_INTERVAL_MS = 1_500

export interface ScanService {
  queue(repositoryId: number): Promise<Scan>
  get(scanId: number, signal?: AbortSignal): Promise<Scan>
  listForRepository(
    repositoryId: number,
    limit?: number,
    signal?: AbortSignal,
  ): Promise<ScanListResponse>
}

export function createScanService(client: ApiClient): ScanService {
  return {
    async queue(repositoryId) {
      const result = await client.request<Scan>(`${REPOSITORIES_PATH}/${repositoryId}/scans`, {
        method: 'POST',
        auth: true,
        // 202 Accepted: the scan is queued, not finished. The client polls.
        acceptStatuses: [202],
      })
      return result.data
    },

    async get(scanId, signal) {
      const result = await client.request<Scan>(`${SCANS_PATH}/${scanId}`, { auth: true, signal })
      return result.data
    },

    async listForRepository(repositoryId, limit = 10, signal) {
      const result = await client.request<ScanListResponse>(
        `${REPOSITORIES_PATH}/${repositoryId}/scans?limit=${limit}&offset=0`,
        { auth: true, signal },
      )
      return result.data
    },
  }
}
