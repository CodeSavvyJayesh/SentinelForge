/** Mirrors backend/app/schemas/project.py */
export interface Project {
  id: number
  owner_id: number
  name: string
  description: string | null
  repository_url: string | null
  default_branch: string
  language: string | null
  created_at: string
  updated_at: string
}

export interface ProjectListResponse {
  items: Project[]
  total: number
  limit: number
  offset: number
}

export interface ProjectCreateInput {
  name: string
  description?: string | null
  repository_url?: string | null
  default_branch?: string
}

export type ProjectUpdateInput = Partial<ProjectCreateInput>

export interface ProjectQuery {
  search?: string
  limit?: number
  offset?: number
}
