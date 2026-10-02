import type { ApiClient } from './apiClient'
import type { Patch } from '../types/patch'

export const FINDINGS_PATH = '/api/v1/findings'
export const PATCHES_PATH = '/api/v1/patches'

/** How often the UI asks whether the model has finished.
 *
 * Same interval as explanations, for the same reason: a generation on a CPU
 * takes tens of seconds, and asking every 1.5s would be forty pointless
 * requests per proposal.
 */
export const PATCH_POLL_INTERVAL_MS = 3_000

/** How often to ask while a re-scan is running.
 *
 * Much faster than the generation poll: a validation is the analyser run
 * twice, which takes milliseconds. Waiting three seconds to show a verdict
 * that was ready after one would make the check feel like an afterthought.
 */
export const VALIDATION_POLL_INTERVAL_MS = 1_000

export interface PatchService {
  request(findingId: number): Promise<Patch>
  get(patchId: number, signal?: AbortSignal): Promise<Patch>
  /** The latest attempt, or null when one has never been requested. */
  latestForFinding(findingId: number, signal?: AbortSignal): Promise<Patch | null>
  /** Queue a re-scan of a proposal. Returns the patch with the queued check. */
  requestValidation(patchId: number): Promise<Patch>
}

export function createPatchService(client: ApiClient): PatchService {
  return {
    async request(findingId) {
      const result = await client.request<Patch>(`${FINDINGS_PATH}/${findingId}/patch`, {
        method: 'POST',
        auth: true,
        // 202 Accepted: queued, not generated. The client polls.
        acceptStatuses: [202],
      })
      return result.data
    },

    async get(patchId, signal) {
      const result = await client.request<Patch>(`${PATCHES_PATH}/${patchId}`, {
        auth: true,
        signal,
      })
      return result.data
    },

    async latestForFinding(findingId, signal) {
      const result = await client.request<Patch | null>(`${FINDINGS_PATH}/${findingId}/patch`, {
        auth: true,
        signal,
        acceptStatuses: [200, 204],
      })
      // 204 means nobody has ever asked. That is different from "asked and was
      // refused", and the panel says something different for each.
      return result.status === 204 ? null : result.data
    },

    async requestValidation(patchId) {
      const result = await client.request<Patch>(`${PATCHES_PATH}/${patchId}/validation`, {
        method: 'POST',
        auth: true,
        // 202 Accepted: queued, not checked. The verdict arrives by polling.
        acceptStatuses: [202],
      })
      return result.data
    },
  }
}
