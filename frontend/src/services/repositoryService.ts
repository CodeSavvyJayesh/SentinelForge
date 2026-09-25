import type { ApiClient } from './apiClient'
import type {
  Repository,
  RepositoryConnectInput,
  RepositoryListResponse,
} from '../types/repository'

export const PROJECTS_PATH = '/api/v1/projects'
export const REPOSITORIES_PATH = '/api/v1/repositories'

/** Ingestion reads and hashes every file, so it is slower than a normal call. */
export const INGEST_TIMEOUT_MS = 180_000

export interface RepositoryService {
  listForProject(projectId: number, signal?: AbortSignal): Promise<RepositoryListResponse>
  upload(projectId: number, file: File): Promise<Repository>
  connectGit(projectId: number, input: RepositoryConnectInput): Promise<Repository>
  remove(repositoryId: number): Promise<void>
}

export function createRepositoryService(client: ApiClient): RepositoryService {
  return {
    async listForProject(projectId, signal) {
      const result = await client.request<RepositoryListResponse>(
        `${PROJECTS_PATH}/${projectId}/repositories`,
        { auth: true, signal },
      )
      return result.data
    },

    async upload(projectId, file) {
      // FormData, not JSON: the API takes a real multipart upload, and the
      // browser adds the boundary header itself.
      const form = new FormData()
      form.append('file', file)
      const result = await client.request<Repository>(
        `${PROJECTS_PATH}/${projectId}/repositories/upload`,
        { method: 'POST', body: form, auth: true, timeoutMs: INGEST_TIMEOUT_MS },
      )
      return result.data
    },

    async connectGit(projectId, input) {
      const result = await client.request<Repository>(
        `${PROJECTS_PATH}/${projectId}/repositories/git`,
        {
          method: 'POST',
          body: { repository_url: input.repository_url, branch: input.branch ?? null },
          auth: true,
          timeoutMs: INGEST_TIMEOUT_MS,
        },
      )
      return result.data
    },

    async remove(repositoryId) {
      await client.request<null>(`${REPOSITORIES_PATH}/${repositoryId}`, {
        method: 'DELETE',
        auth: true,
      })
    },
  }
}
