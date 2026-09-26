import { useEffect, useState } from 'react'

import { ErrorState } from './ErrorState'
import { LoadingState } from './LoadingState'
import { knowledgeService } from '../services/api'
import { ApiError, toApiError } from '../services/apiClient'
import type { FindingKnowledgeResponse } from '../types/knowledge'
import { MATCH_LABELS, SOURCE_LABELS } from '../types/knowledge'

/**
 * Strip the heading the indexer prefixed onto every passage.
 *
 * Chunks are stored as "CWE-89: SQL Injection — Mitigations\n<text>", because a
 * passage's vector has to carry its own subject or it sits next to every other
 * piece of generic advice. On screen that line is already the attribution just
 * above it, so showing it again is noise.
 */
function passageBody(text: string, title: string, section: string): string {
  const heading = `${title} — ${section}\n`
  return text.startsWith(heading) ? text.slice(heading.length) : text
}

type State =
  | { status: 'loading' }
  | { status: 'ready'; knowledge: FindingKnowledgeResponse }
  | { status: 'error'; error: ApiError }

/**
 * What the knowledge base says about one finding.
 *
 * Loaded when the finding is expanded rather than with the list: a page of
 * fifty findings would otherwise fire fifty retrievals, forty-nine of which
 * nobody reads.
 *
 * Every passage shows where it came from and why it was retrieved. Security
 * advice a developer cannot trace back to a source is advice they cannot check,
 * and this project's own notes are labelled as ours rather than presented under
 * the same badge as MITRE's text.
 */
export function FindingKnowledge({ findingId }: { findingId: number }) {
  const [state, setState] = useState<State>({ status: 'loading' })

  useEffect(() => {
    const controller = new AbortController()
    knowledgeService
      .forFinding(findingId, controller.signal)
      .then((knowledge) => {
        if (controller.signal.aborted) return
        setState({ status: 'ready', knowledge })
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted) return
        setState({ status: 'error', error: toApiError(caught) })
      })
    return () => controller.abort()
  }, [findingId])

  if (state.status === 'loading') {
    return <LoadingState label="Looking this up…" />
  }

  if (state.status === 'error') {
    // A knowledge base nobody has built is a fact about this installation, not
    // about the vulnerability. The distinction is worth the extra branch.
    const notBuilt = state.error.code === 'KNOWLEDGE_BASE_NOT_BUILT'
    return (
      <ErrorState
        title={notBuilt ? 'No security knowledge base yet' : 'Could not load reference material'}
        message={state.error.message}
        code={notBuilt ? undefined : state.error.code}
        requestId={notBuilt ? undefined : state.error.requestId}
      />
    )
  }

  const { passages } = state.knowledge
  if (passages.length === 0) {
    return (
      <p className="knowledge__empty">
        The knowledge base has nothing indexed for this weakness. The finding itself still stands.
      </p>
    )
  }

  return (
    <section className="knowledge" aria-label="Reference material">
      <h4 className="knowledge__heading">What this means, and how to fix it</h4>
      <ul className="knowledge__list">
        {passages.map((passage) => (
          <li key={passage.id} className={`knowledge__item knowledge__item--${passage.source.toLowerCase()}`}>
            <p className="knowledge__attribution">
              <span className={`source-tag source-tag--${passage.source.toLowerCase()}`}>
                {SOURCE_LABELS[passage.source]}
              </span>
              {passage.url ? (
                <a className="link" href={passage.url} target="_blank" rel="noreferrer noopener">
                  {passage.external_id}
                </a>
              ) : (
                <span>{passage.external_id}</span>
              )}
              <span className="knowledge__section">{passage.section}</span>
              <span className="knowledge__match">{MATCH_LABELS[passage.matched_by]}</span>
            </p>
            {/* Reference text, rendered by React as text — never as markup. */}
            <p className="knowledge__text">
              {passageBody(passage.text, passage.document_title, passage.section)}
            </p>
          </li>
        ))}
      </ul>
      <p className="knowledge__query">
        Retrieved for: <code>{state.knowledge.query}</code>
      </p>
    </section>
  )
}
