import type { ApiClient } from './apiClient'
import type {
  Project,
  ProjectCreateInput,
  ProjectListResponse,
  ProjectQuery,
  ProjectUpdateInput,
} from '../types/project'

export const PROJECTS_PATH = '/api/v1/projects'

export interface ProjectService {
  list(query?: ProjectQuery, signal?: AbortSignal): Promise<ProjectListResponse>
  get(id: number, signal?: AbortSignal): Promise<Project>
  create(input: ProjectCreateInput): Promise<Project>
  update(id: number, input: ProjectUpdateInput): Promise<Project>
  remove(id: number): Promise<void>
}

function buildQuery({ search, limit = 20, offset = 0 }: ProjectQuery = {}): string {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) })
  // Only send a search term when there is one: an empty param would filter on "".
  if (search?.trim()) params.set('search', search.trim())
  return params.toString()
}

export function createProjectService(client: ApiClient): ProjectService {
  return {
    async list(query, signal) {
      const result = await client.request<ProjectListResponse>(
        `${PROJECTS_PATH}?${buildQuery(query)}`,
        { auth: true, signal },
      )
      return result.data
    },

    async get(id, signal) {
      const result = await client.request<Project>(`${PROJECTS_PATH}/${id}`, {
        auth: true,
        signal,
      })
      return result.data
    },

    async create(input) {
      const result = await client.request<Project>(PROJECTS_PATH, {
        method: 'POST',
        body: input,
        auth: true,
      })
      return result.data
    },

    async update(id, input) {
      const result = await client.request<Project>(`${PROJECTS_PATH}/${id}`, {
        method: 'PATCH',
        body: input,
        auth: true,
      })
      return result.data
    },

    async remove(id) {
      await client.request<null>(`${PROJECTS_PATH}/${id}`, { method: 'DELETE', auth: true })
    },
  }
}
