import type { ApiClient } from './apiClient'
import type { Dashboard } from '../types/dashboard'

export const DASHBOARD_PATH = '/api/v1/dashboard'

export interface DashboardService {
  /** Everything the signed-in user owns. Takes no id: who is asking is the only input. */
  load(signal?: AbortSignal): Promise<Dashboard>
}

export function createDashboardService(client: ApiClient): DashboardService {
  return {
    async load(signal) {
      const result = await client.request<Dashboard>(DASHBOARD_PATH, { auth: true, signal })
      return result.data
    },
  }
}
