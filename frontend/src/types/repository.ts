/** Mirrors backend/app/schemas/repository.py */

export type RepositorySource = 'UPLOAD' | 'GIT'
export type RepositoryStatus = 'PENDING' | 'INGESTING' | 'READY' | 'FAILED'

export interface Repository {
  id: number
  project_id: number
  source: RepositorySource
  status: RepositoryStatus
  origin: string
  branch: string | null
  commit_hash: string | null
  file_count: number
  total_bytes: number
  primary_language: string | null
  /** Bytes per language, biggest first. Never file counts. */
  language_breakdown: Record<string, number> | null
  error_message: string | null
  ingested_at: string | null
  /** When static analysis last ran; null means never. */
  analyzed_at: string | null
  created_at: string
  updated_at: string
}

export interface RepositoryListResponse {
  items: Repository[]
  total: number
}

export interface RepositoryConnectInput {
  repository_url: string
  branch?: string | null
}
