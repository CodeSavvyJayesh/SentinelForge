import type { ApiClient } from './apiClient'
import type { Explanation } from '../types/explanation'

export const FINDINGS_PATH = '/api/v1/findings'
export const EXPLANATIONS_PATH = '/api/v1/explanations'

/** How often the UI asks whether the model has finished.
 *
 * Slower than the scan poll: a generation on a CPU takes tens of seconds, and
 * asking every 1.5s would be forty pointless requests per explanation.
 */
export const EXPLANATION_POLL_INTERVAL_MS = 3_000

export interface ExplanationService {
  request(findingId: number): Promise<Explanation>
  get(explanationId: number, signal?: AbortSignal): Promise<Explanation>
  /** The latest attempt, or null when one has never been requested. */
  latestForFinding(findingId: number, signal?: AbortSignal): Promise<Explanation | null>
}

export function createExplanationService(client: ApiClient): ExplanationService {
  return {
    async request(findingId) {
      const result = await client.request<Explanation>(
        `${FINDINGS_PATH}/${findingId}/explanation`,
        {
          method: 'POST',
          auth: true,
          // 202 Accepted: queued, not generated. The client polls.
          acceptStatuses: [202],
        },
      )
      return result.data
    },

    async get(explanationId, signal) {
      const result = await client.request<Explanation>(
        `${EXPLANATIONS_PATH}/${explanationId}`,
        { auth: true, signal },
      )
      return result.data
    },

    async latestForFinding(findingId, signal) {
      const result = await client.request<Explanation | null>(
        `${FINDINGS_PATH}/${findingId}/explanation`,
        { auth: true, signal, acceptStatuses: [200, 204] },
      )
      // 204 means nobody has ever asked. That is different from "asked and got
      // nothing", and the panel says something different for each.
      return result.status === 204 ? null : result.data
    },
  }
}
