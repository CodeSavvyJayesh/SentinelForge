import { useCallback, useEffect, useState } from 'react'

import { ErrorState } from './ErrorState'
import { explanationService } from '../services/api'
import { EXPLANATION_POLL_INTERVAL_MS } from '../services/explanationService'
import { ApiError, toApiError } from '../services/apiClient'
import type { Explanation } from '../types/explanation'
import { ACTIVE_EXPLANATION_STATUSES } from '../types/explanation'
import { SOURCE_LABELS } from '../types/knowledge'

type State =
  | { status: 'loading' }
  | { status: 'none' } // never requested
  | { status: 'have'; explanation: Explanation }
  | { status: 'error'; error: ApiError }

/**
 * What the local model says about one finding.
 *
 * Every element of this panel exists to let a developer weigh the text rather
 * than only read it. The model name and prompt version say what produced it.
 * The citations link back to the passages it was given — resolved on the
 * server from our own knowledge base, never from anything the model wrote.
 * And when the output had to be cleaned up, that is shown rather than hidden,
 * because an invented citation is the clearest evidence there is that a model
 * is filling gaps.
 *
 * The panel never claims the explanation is correct. It says who generated it,
 * from what, and what had to be removed.
 */
export function FindingExplanation({ findingId }: { findingId: number }) {
  const [state, setState] = useState<State>({ status: 'loading' })
  const [requesting, setRequesting] = useState(false)

  const load = useCallback(
    (signal?: AbortSignal) =>
      explanationService
        .latestForFinding(findingId, signal)
        .then((explanation) => {
          if (signal?.aborted) return
          setState(explanation ? { status: 'have', explanation } : { status: 'none' })
        })
        .catch((caught: unknown) => {
          if (signal?.aborted) return
          setState({ status: 'error', error: toApiError(caught) })
        }),
    [findingId],
  )

  useEffect(() => {
    const controller = new AbortController()
    void load(controller.signal)
    return () => controller.abort()
  }, [load])

  // Poll while the model is working. Generation on a CPU is tens of seconds,
  // so this is deliberately slower than the scan poll.
  const active =
    state.status === 'have' && ACTIVE_EXPLANATION_STATUSES.includes(state.explanation.status)
  useEffect(() => {
    if (!active) return
    const controller = new AbortController()
    const timer = setTimeout(() => void load(controller.signal), EXPLANATION_POLL_INTERVAL_MS)
    return () => {
      controller.abort()
      clearTimeout(timer)
    }
  }, [active, state, load])

  async function generate() {
    setRequesting(true)
    try {
      setState({ status: 'have', explanation: await explanationService.request(findingId) })
    } catch (caught: unknown) {
      setState({ status: 'error', error: toApiError(caught) })
    } finally {
      setRequesting(false)
    }
  }

  if (state.status === 'loading') return null

  if (state.status === 'error') {
    return (
      <ErrorState
        title="Could not load the explanation"
        message={state.error.message}
        code={state.error.code}
        requestId={state.error.requestId}
      />
    )
  }

  const explanation = state.status === 'have' ? state.explanation : null
  const working = explanation !== null && ACTIVE_EXPLANATION_STATUSES.includes(explanation.status)

  return (
    <section className="explanation" aria-label="Explanation from the local model">
      <div className="explanation__header">
        <h4 className="explanation__heading">Explanation</h4>
        <button
          type="button"
          className="button button--small"
          onClick={() => void generate()}
          disabled={working || requesting}
        >
          {working
            ? explanation?.status === 'QUEUED'
              ? 'Queued…'
              : 'Generating…'
            : explanation
              ? 'Generate again'
              : 'Explain this'}
        </button>
      </div>

      {explanation === null && (
        <p className="explanation__hint">
          A local model can explain this finding using the reference material above. Nothing
          leaves your machine.
        </p>
      )}

      {working && (
        <p className="explanation__hint" role="status">
          {explanation?.status === 'QUEUED'
            ? 'Waiting for the model…'
            : 'The model is reading the passages above. This takes a while on a CPU.'}
        </p>
      )}

      {explanation?.status === 'FAILED' && (
        <ErrorState
          title="The model could not explain this"
          message={explanation.error_message ?? 'Generation did not finish.'}
        />
      )}

      {explanation?.status === 'COMPLETED' && <Completed explanation={explanation} />}
    </section>
  )
}

function Completed({ explanation }: { explanation: Explanation }) {
  return (
    <>
      {/* Warnings first: a reader should meet the caveat before the prose it
          applies to, not after they have already believed it. */}
      {!explanation.grounded && (
        <p className="explanation__warning" role="note">
          This explanation cites none of the reference passages, so it rests on the model alone.
          Weigh it accordingly.
        </p>
      )}
      {explanation.dropped_citations > 0 && (
        <p className="explanation__warning" role="note">
          {explanation.dropped_citations} citation
          {explanation.dropped_citations === 1 ? '' : 's'} referred to material the model was
          never given, and {explanation.dropped_citations === 1 ? 'was' : 'were'} removed.
        </p>
      )}
      {explanation.links_removed > 0 && (
        <p className="explanation__warning" role="note">
          {explanation.links_removed} link{explanation.links_removed === 1 ? '' : 's'} written by
          the model {explanation.links_removed === 1 ? 'was' : 'were'} removed. Only links to
          indexed sources are shown.
        </p>
      )}

      {/* Model output, rendered by React as text — never as markup. */}
      <dl className="explanation__body">
        <dt>What is wrong</dt>
        <dd>{explanation.summary}</dd>
        <dt>What it allows</dt>
        <dd>{explanation.impact}</dd>
        <dt>How to fix it</dt>
        <dd>{explanation.remediation}</dd>
      </dl>

      {explanation.citations.length > 0 && (
        <div className="explanation__citations">
          <span className="explanation__citations-label">Based on</span>
          <ul>
            {explanation.citations.map((citation) => (
              <li key={citation.chunk_id}>
                <span className="explanation__marker">[{citation.number}]</span>{' '}
                {citation.url ? (
                  <a className="link" href={citation.url} target="_blank" rel="noreferrer noopener">
                    {citation.external_id}
                  </a>
                ) : (
                  <span>{citation.external_id}</span>
                )}{' '}
                <span className="explanation__source">
                  {SOURCE_LABELS[citation.source]} · {citation.section}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <p className="explanation__provenance">
        Generated locally by <code>{explanation.model}</code> (prompt v
        {explanation.prompt_version})
        {explanation.duration_ms !== null &&
          ` in ${(explanation.duration_ms / 1000).toFixed(1)}s`}
        . Generated text, not a verdict — the finding itself comes from the analyser.
      </p>
    </>
  )
}
