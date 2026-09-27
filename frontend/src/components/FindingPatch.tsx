import { useCallback, useEffect, useState } from 'react'

import { ErrorState } from './ErrorState'
import { patchService } from '../services/api'
import { PATCH_POLL_INTERVAL_MS } from '../services/patchService'
import { ApiError, toApiError } from '../services/apiClient'
import type { Patch } from '../types/patch'
import { ACTIVE_PATCH_STATUSES, parseDiff } from '../types/patch'

type State =
  | { status: 'loading' }
  | { status: 'none' } // never requested
  | { status: 'have'; patch: Patch }
  | { status: 'error'; error: ApiError }

/**
 * A proposed change to the code, and a refusal to pretend it is more.
 *
 * This panel shows a diff a language model wrote. Everything about its design
 * assumes the reader might otherwise trust it too much:
 *
 * - The notice comes **before** the diff, because a caveat read afterwards is
 *   read by somebody who has already believed the thing.
 * - There is no "Apply" button. Not disabled — absent. The only way this code
 *   reaches a repository is if a person copies it and decides to.
 * - The provenance line names the model and says the change has not been run.
 *
 * Phase 11 adds validation by applying the patch to a throwaway copy and
 * re-scanning it. Until then, `validated` is false and this panel says so.
 */
export function FindingPatch({ findingId }: { findingId: number }) {
  const [state, setState] = useState<State>({ status: 'loading' })
  const [requesting, setRequesting] = useState(false)
  const [copied, setCopied] = useState(false)

  const load = useCallback(
    (signal?: AbortSignal) =>
      patchService
        .latestForFinding(findingId, signal)
        .then((patch) => {
          if (signal?.aborted) return
          setState(patch ? { status: 'have', patch } : { status: 'none' })
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

  const active = state.status === 'have' && ACTIVE_PATCH_STATUSES.includes(state.patch.status)
  useEffect(() => {
    if (!active) return
    const controller = new AbortController()
    const timer = setTimeout(() => void load(controller.signal), PATCH_POLL_INTERVAL_MS)
    return () => {
      controller.abort()
      clearTimeout(timer)
    }
  }, [active, state, load])

  async function generate() {
    setRequesting(true)
    setCopied(false)
    try {
      setState({ status: 'have', patch: await patchService.request(findingId) })
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
        title="Could not load the proposed change"
        message={state.error.message}
        code={state.error.code}
        requestId={state.error.requestId}
      />
    )
  }

  const patch = state.status === 'have' ? state.patch : null
  const working = patch !== null && ACTIVE_PATCH_STATUSES.includes(patch.status)

  async function copyDiff(diff: string) {
    try {
      await navigator.clipboard.writeText(diff)
      setCopied(true)
    } catch {
      // Clipboard access can be refused, and there is nothing to do about it.
      // The diff is on screen and selectable either way.
      setCopied(false)
    }
  }

  return (
    <section className="patch" aria-label="Proposed change from the local model">
      <div className="patch__header">
        <h4 className="patch__heading">Proposed change</h4>
        <button
          type="button"
          className="button button--small"
          onClick={() => void generate()}
          disabled={working || requesting}
        >
          {working
            ? patch?.status === 'QUEUED'
              ? 'Queued…'
              : 'Writing…'
            : patch
              ? 'Try again'
              : 'Suggest a fix'}
        </button>
      </div>

      {patch === null && (
        <p className="patch__hint">
          A local model can propose a change to this code. It is a suggestion to review, not a
          fix — nothing is applied to your files.
        </p>
      )}

      {working && (
        <p className="patch__hint" role="status">
          {patch?.status === 'QUEUED'
            ? 'Waiting for the model…'
            : 'The model is rewriting the code. This takes a while on a CPU.'}
        </p>
      )}

      {patch?.status === 'FAILED' && (
        <>
          <ErrorState
            title="No change was proposed"
            message={patch.error_message ?? 'Generation did not finish.'}
          />
          {patch.rejected_code !== null && (
            // A refusal is a verdict on the model's work, and the check that
            // produced it is a heuristic that can be wrong about a correct
            // fix. Showing what was thrown away lets a developer judge the
            // judgement — and copy it themselves if it was right after all.
            <details className="patch__rejected">
              <summary>What the model returned</summary>
              <pre className="patch__diff">
                <code className="patch__line patch__line--context">{patch.rejected_code}</code>
              </pre>
              <p className="patch__provenance">
                Not applied and not checked — this is the raw text the proposal was built from.
              </p>
            </details>
          )}
        </>
      )}

      {patch?.status === 'PROPOSED' && patch.diff !== null && (
        <Proposed patch={patch} diff={patch.diff} copied={copied} onCopy={copyDiff} />
      )}
    </section>
  )
}

function Proposed({
  patch,
  diff,
  copied,
  onCopy,
}: {
  patch: Patch
  diff: string
  copied: boolean
  onCopy: (diff: string) => Promise<void>
}) {
  return (
    <>
      {/* Before the diff, deliberately. */}
      <p className="patch__warning" role="note">
        <strong>Not tested.</strong> This change was written by a language model and has not been
        applied, compiled, or re-scanned. Read it before you use it.
      </p>

      {patch.gutters_stripped > 0 && (
        <p className="patch__warning" role="note">
          The model returned this code with line numbers attached, which were removed. Check the
          result carefully.
        </p>
      )}

      <div className="patch__filebar">
        <code className="patch__file">
          {patch.file_path}
          {patch.first_line !== null && `:${patch.first_line}`}
        </code>
        <span className="patch__counts">
          <span className="patch__count patch__count--added">+{patch.lines_added}</span>
          <span className="patch__count patch__count--removed">−{patch.lines_removed}</span>
        </span>
        <button
          type="button"
          className="button button--small button--quiet"
          onClick={() => void onCopy(diff)}
        >
          {copied ? 'Copied' : 'Copy diff'}
        </button>
      </div>

      {/* Rendered by React as text, never as markup — this string came from a
          model, by way of a file from somebody else's repository. */}
      <pre className="patch__diff" aria-label="Unified diff of the proposed change">
        {parseDiff(diff).map((line, index) => (
          <code key={index} className={`patch__line patch__line--${line.kind}`}>
            {line.text === '' ? ' ' : line.text}
          </code>
        ))}
      </pre>

      {patch.rationale !== null && <p className="patch__rationale">{patch.rationale}</p>}

      <p className="patch__provenance">
        Written locally by <code>{patch.model}</code> (prompt v{patch.prompt_version})
        {patch.duration_ms !== null && ` in ${(patch.duration_ms / 1000).toFixed(1)}s`}. Nothing on
        disk was changed.
      </p>
    </>
  )
}
