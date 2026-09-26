/** Mirrors backend/app/schemas/explanation.py */

import type { KnowledgeSourceName } from './knowledge'

export type ExplanationStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED'

/** Still working — the UI polls while one of these is true. */
export const ACTIVE_EXPLANATION_STATUSES: ExplanationStatus[] = ['QUEUED', 'RUNNING']

/** A passage the model cited, resolved back to the real document.
 *
 * The model produced only the number. Everything else here was read from our
 * own knowledge base, which is why the link is safe to render.
 */
export interface ExplanationCitation {
  number: number
  chunk_id: number
  source: KnowledgeSourceName
  external_id: string
  document_title: string
  section: string
  url: string | null
}

export interface Explanation {
  id: number
  finding_id: number
  status: ExplanationStatus
  attempts: number

  summary: string | null
  impact: string | null
  remediation: string | null

  /** Provenance: which model, and which version of our prompt. */
  model: string | null
  prompt_version: number | null
  citations: ExplanationCitation[]
  /** True when at least one citation survived verification. */
  grounded: boolean

  /** What the output contract had to remove before this was stored. */
  dropped_citations: number
  links_removed: number

  duration_ms: number | null
  prompt_tokens: number | null
  completion_tokens: number | null
  error_message: string | null
  created_at: string
  finished_at: string | null
}
