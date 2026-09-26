/** Mirrors backend/app/schemas/knowledge.py */

export type KnowledgeSourceName = 'CWE' | 'OWASP' | 'SENTINELFORGE'

/** Why a passage was retrieved — shown so the reader can weigh it. */
export type MatchReason = 'rule' | 'cwe' | 'owasp' | 'semantic'

export interface KnowledgePassage {
  id: number
  source: KnowledgeSourceName
  external_id: string
  document_title: string
  section: string
  text: string
  url: string | null
  source_version: string | null
  score: number
  matched_by: MatchReason
}

export interface FindingKnowledgeResponse {
  finding_id: number
  rule_id: string
  cwe_id: string | null
  owasp_category: string | null
  /** The text that was embedded to search with, so a result can be reproduced. */
  query: string
  passages: KnowledgePassage[]
}

export interface KnowledgeStatus {
  built: boolean
  documents: number
  chunks: number
  embedded_chunks: number
  by_source: Record<string, number>
  embedding_models: string[]
  source_versions: Record<string, string>
  built_at: string | null
}

/** How each source is labelled in the UI.
 *
 * SentinelForge's own notes are named as ours. Presenting them under the same
 * badge as MITRE's text would borrow authority we have not earned.
 */
export const SOURCE_LABELS: Record<KnowledgeSourceName, string> = {
  CWE: 'MITRE CWE',
  OWASP: 'OWASP',
  SENTINELFORGE: 'SentinelForge note',
}

export const MATCH_LABELS: Record<MatchReason, string> = {
  rule: 'written for this rule',
  cwe: 'this weakness',
  owasp: 'this OWASP category',
  semantic: 'related',
}
