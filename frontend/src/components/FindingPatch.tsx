import { useCallback, useEffect, useState } from 'react'

import { ErrorState } from './ErrorState'
import { patchService } from '../services/api'
import { PATCH_POLL_INTERVAL_MS, VALIDATION_POLL_INTERVAL_MS } from '../services/patchService'
import { ApiError, toApiError } from '../services/apiClient'
import type { CheckOutcome, Patch, PatchValidation, ValidationState } from '../types/patch'
import {
  ACTIVE_PATCH_STATUSES,
  CHECK_LABELS,
  isSettling,
  parseDiff,
  validationState,
} from '../types/patch'

type State =
  | { status: 'loading' }
  | { status: 'none' } // never requested
  | { status: 'have'; patch: Patch }
  | { status: 'error'; error: ApiError }

/**
 * A proposed change to the code, and exactly as much confidence as it earned.
 *
 * This panel shows a diff a language model wrote. Everything about its design
 * assumes the reader might otherwise trust it too much:
 *
 * - The verdict comes **before** the diff, because a caveat read afterwards is
 *   read by somebody who has already believed the thing.
 * - There is no "Apply" button. Not disabled — absent. The only way this code
 *   reaches a repository is if a person copies it and decides to.
 * - A verdict never appears without its evidence: each check that was made is
 *   listed with how it came out, including the ones that were skipped.
 *
 * Every proposal is checked automatically — applied to a throwaway copy of the
 * code and scanned again. "Checked by re-scan" means the finding is no longer
 * detected, nothing new is, and the change is not a deletion. It does not mean
 * the program still behaves the same, and the panel says that too. A check
 * that could not run is shown as exactly that, never as a rejection.
 */
export function FindingPatch({ findingId }: { findingId: number }) {
  const [state, setState] = useState<State>({ status: 'loading' })
  const [requesting, setRequesting] = useState(false)
  const [copied, setCopied] = useState(false)
  const [checking, setChecking] = useState(false)

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

  // Poll while anything is in flight: the model writing, or the re-scan
  // running. The re-scan is polled faster because it finishes in milliseconds.
  const active = state.status === 'have' && isSettling(state.patch)
  const interval =
    state.status === 'have' && ACTIVE_PATCH_STATUSES.includes(state.patch.status)
      ? PATCH_POLL_INTERVAL_MS
      : VALIDATION_POLL_INTERVAL_MS
  useEffect(() => {
    if (!active) return
    const controller = new AbortController()
    const timer = setTimeout(() => void load(controller.signal), interval)
    return () => {
      controller.abort()
      clearTimeout(timer)
    }
  }, [active, interval, state, load])

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

  async function checkAgain(patchId: number) {
    setChecking(true)
    try {
      setState({ status: 'have', patch: await patchService.requestValidation(patchId) })
    } catch (caught: unknown) {
      setState({ status: 'error', error: toApiError(caught) })
    } finally {
      setChecking(false)
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
        <Proposed
          patch={patch}
          diff={patch.diff}
          copied={copied}
          onCopy={copyDiff}
          checking={checking}
          onCheck={() => void checkAgain(patch.id)}
        />
      )}
    </section>
  )
}

function Proposed({
  patch,
  diff,
  copied,
  onCopy,
  checking,
  onCheck,
}: {
  patch: Patch
  diff: string
  copied: boolean
  onCopy: (diff: string) => Promise<void>
  checking: boolean
  onCheck: () => void
}) {
  return (
    <>
      {/* Before the diff, deliberately. */}
      <Verdict patch={patch} checking={checking} onCheck={onCheck} />

      {patch.gutters_stripped > 0 && (
        <p className="patch__warning" role="note">
          The model returned this code with line numbers attached, which were removed. Check the
          result carefully.
        </p>
      )}

      {patch.reindented && (
        <p className="patch__warning" role="note">
          The model returned this code without indentation, which was restored to match the
          surrounding lines. Check that it sits where it should.
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

const VERDICT_CLASS: Record<ValidationState, string> = {
  unchecked: 'patch__verdict--caution',
  checking: 'patch__verdict--pending',
  validated: 'patch__verdict--passed',
  rejected: 'patch__verdict--rejected',
  undetermined: 'patch__verdict--caution',
}

/**
 * What the re-scan said about this change, with the evidence under it.
 *
 * Five states, and the wording of each is the point. "Checked by re-scan" is
 * never shortened to "fixed" or "safe"; a rejection says what the scanner saw;
 * and a check that could not run says so instead of borrowing either verdict.
 */
function Verdict({
  patch,
  checking,
  onCheck,
}: {
  patch: Patch
  checking: boolean
  onCheck: () => void
}) {
  const verdict = validationState(patch)
  const validation = patch.validation

  return (
    <div
      className={`patch__verdict ${VERDICT_CLASS[verdict]}`}
      role={verdict === 'checking' ? 'status' : 'note'}
    >
      {verdict === 'unchecked' && (
        <p>
          <strong>Not checked.</strong> This change was written by a language model and has not
          been re-scanned. Read it before you use it.
        </p>
      )}

      {verdict === 'checking' && (
        <p>
          <strong>Checking…</strong> Applying this change to a throwaway copy of your code and
          scanning it again. Your files are not touched.
        </p>
      )}

      {verdict === 'validated' && (
        <p>
          <strong>Checked by re-scan.</strong> Applied to a throwaway copy and scanned again: the
          finding is no longer detected and nothing new appeared. That does not show the program
          still behaves the same — read it before you use it. The finding stays open until your
          real code is scanned without it.
        </p>
      )}

      {verdict === 'rejected' && (
        <p>
          <strong>Rejected by re-scan.</strong> Applied to a throwaway copy and scanned again, this
          change did not hold up. Do not use it as it stands.
        </p>
      )}

      {verdict === 'undetermined' && (
        <p>
          <strong>Could not be checked.</strong>{' '}
          {validation?.error_message ?? 'The re-scan did not finish.'} This says nothing about the
          change itself.
        </p>
      )}

      {validation !== null && validation.checks.length > 0 && <Checks validation={validation} />}

      {verdict !== 'checking' && (
        <button
          type="button"
          className="button button--small button--quiet"
          onClick={onCheck}
          disabled={checking}
        >
          {checking ? 'Queueing…' : verdict === 'unchecked' ? 'Check this change' : 'Check again'}
        </button>
      )}
    </div>
  )
}

/** Words as well as a symbol: an outcome must not be carried by colour alone. */
const OUTCOME_TEXT: Record<CheckOutcome, { symbol: string; label: string }> = {
  passed: { symbol: '✓', label: 'Passed' },
  failed: { symbol: '✗', label: 'Failed' },
  skipped: { symbol: '–', label: 'Not checked' },
}

function Checks({ validation }: { validation: PatchValidation }) {
  return (
    <>
      <ul className="patch__checks">
        {validation.checks.map((check) => {
          const outcome = OUTCOME_TEXT[check.outcome] ?? OUTCOME_TEXT.skipped
          return (
            <li key={check.key} className={`patch__check patch__check--${check.outcome}`}>
              <span className="patch__check-outcome">
                <span aria-hidden="true">{outcome.symbol}</span> {outcome.label}
              </span>
              <span className="patch__check-name">{CHECK_LABELS[check.key] ?? check.key}</span>
              {/* Written by the server from the scan, shown as text. */}
              <span className="patch__check-detail">{check.detail}</span>
            </li>
          )
        })}
      </ul>

      {validation.new_findings.length > 0 && (
        <p className="patch__verdict-note">
          Appeared after the change:{' '}
          {validation.new_findings
            .map((item) => `${item.rule_id} ${item.title} (${item.file_path}:${item.line})`)
            .join('; ')}
          .
        </p>
      )}

      {validation.also_resolved > 0 && (
        <p className="patch__verdict-note">
          This change also made {validation.also_resolved} other finding
          {validation.also_resolved === 1 ? '' : 's'} disappear. A fix for one line that removes
          others deserves a closer look.
        </p>
      )}

      {validation.findings_before !== null && validation.findings_after !== null && (
        <p className="patch__verdict-note">
          Findings in the copy: {validation.findings_before} before, {validation.findings_after}{' '}
          after
          {validation.duration_ms !== null && ` · checked in ${validation.duration_ms} ms`}.
        </p>
      )}
    </>
  )
}
