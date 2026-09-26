import type { ApiClient } from './apiClient'
import type { FindingKnowledgeResponse, KnowledgeStatus } from '../types/knowledge'

export const FINDINGS_PATH = '/api/v1/findings'
export const KNOWLEDGE_PATH = '/api/v1/knowledge'

export interface KnowledgeService {
  forFinding(findingId: number, signal?: AbortSignal): Promise<FindingKnowledgeResponse>
  status(signal?: AbortSignal): Promise<KnowledgeStatus>
}

export function createKnowledgeService(client: ApiClient): KnowledgeService {
  return {
    async forFinding(findingId, signal) {
      const result = await client.request<FindingKnowledgeResponse>(
        `${FINDINGS_PATH}/${findingId}/knowledge`,
        { auth: true, signal },
      )
      return result.data
    },

    async status(signal) {
      const result = await client.request<KnowledgeStatus>(`${KNOWLEDGE_PATH}/status`, {
        auth: true,
        signal,
      })
      return result.data
    },
  }
}
