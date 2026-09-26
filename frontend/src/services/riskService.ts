import type { ApiClient } from './apiClient'
import type { RepositoryRisk, RiskHistory } from '../types/risk'

export const REPOSITORIES_PATH = '/api/v1/repositories'

export interface RiskService {
  forRepository(repositoryId: number, top?: number, signal?: AbortSignal): Promise<RepositoryRisk>
  history(repositoryId: number, limit?: number, signal?: AbortSignal): Promise<RiskHistory>
}

export function createRiskService(client: ApiClient): RiskService {
  return {
    async forRepository(repositoryId, top = 5, signal) {
      const result = await client.request<RepositoryRisk>(
        `${REPOSITORIES_PATH}/${repositoryId}/risk?top=${top}`,
        { auth: true, signal },
      )
      return result.data
    },

    async history(repositoryId, limit = 20, signal) {
      const result = await client.request<RiskHistory>(
        `${REPOSITORIES_PATH}/${repositoryId}/risk/history?limit=${limit}`,
        { auth: true, signal },
      )
      return result.data
    },
  }
}
