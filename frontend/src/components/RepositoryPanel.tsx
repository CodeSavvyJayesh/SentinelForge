import { useId, useState } from 'react'
import type { ChangeEvent, FormEvent } from 'react'

import { EmptyState } from './EmptyState'
import { FindingsPanel } from './FindingsPanel'
import { ErrorState } from './ErrorState'
import { FormField } from './FormField'
import { LoadingState } from './LoadingState'
import { StatusBadge, type StatusTone } from './StatusBadge'
import { useRepositories } from '../hooks/useRepositories'
import { repositoryService } from '../services/api'
import { toApiError } from '../services/apiClient'
import type { Repository, RepositoryStatus } from '../types/repository'
import {
  EMPTY_VALUE,
  formatBytes,
  formatCommit,
  formatDateTime,
  toLanguageShares,
} from '../utils/format'

/** Mirrors the server limit; shown so the user knows before they upload. */
const MAX_UPLOAD_MB = 100

const STATUS_TONE: Record<RepositoryStatus, StatusTone> = {
  READY: 'ok',
  FAILED: 'fail',
  PENDING: 'pending',
  INGESTING: 'pending',
}

const STATUS_LABEL: Record<RepositoryStatus, string> = {
  READY: 'Ready',
  FAILED: 'Failed',
  PENDING: 'Queued',
  INGESTING: 'Ingesting',
}

export function RepositoryPanel({ projectId, defaultBranch }: {
  projectId: number
  defaultBranch: string
}) {
  const { state, reload, prepend, drop } = useRepositories(projectId)

  return (
    <div className="panel">
      <div className="panel__header">
        <h2 className="panel__title">Code</h2>
        <p className="panel__subtitle">
          Upload a zip or clone a public Git repository. Files are stored in an isolated
          workspace and never executed.
        </p>
      </div>

      <ConnectForms
        projectId={projectId}
        defaultBranch={defaultBranch}
        onConnected={(repository) => prepend(repository)}
      />

      {state.status === 'loading' && <LoadingState label="Loading repositories…" />}

      {state.status === 'error' && (
        <ErrorState
          title="Could not load repositories"
          message={state.error.message}
          code={state.error.code}
          requestId={state.error.requestId}
          onRetry={reload}
        />
      )}

      {state.status === 'success' &&
        (state.items.length === 0 ? (
          <EmptyState
            title="No code connected yet"
            message="Add a zip archive or a Git URL above to give SentinelForge something to analyse."
          />
        ) : (
          <ul className="repository-list">
            {state.items.map((repository) => (
              <RepositoryCard
                key={repository.id}
                repository={repository}
                onDeleted={() => drop(repository.id)}
              />
            ))}
          </ul>
        ))}
    </div>
  )
}

function ConnectForms({
  projectId,
  defaultBranch,
  onConnected,
}: {
  projectId: number
  defaultBranch: string
  onConnected: (repository: Repository) => void
}) {
  const [mode, setMode] = useState<'upload' | 'git'>('upload')

  return (
    <div className="repository-connect">
      <div className="tabs" role="tablist" aria-label="How to add code">
        <button
          type="button"
          role="tab"
          aria-selected={mode === 'upload'}
          className={`tab ${mode === 'upload' ? 'tab--active' : ''}`}
          onClick={() => setMode('upload')}
        >
          Upload a zip
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={mode === 'git'}
          className={`tab ${mode === 'git' ? 'tab--active' : ''}`}
          onClick={() => setMode('git')}
        >
          Git URL
        </button>
      </div>

      {mode === 'upload' ? (
        <UploadForm projectId={projectId} onConnected={onConnected} />
      ) : (
        <GitForm projectId={projectId} defaultBranch={defaultBranch} onConnected={onConnected} />
      )}
    </div>
  )
}

function UploadForm({
  projectId,
  onConnected,
}: {
  projectId: number
  onConnected: (repository: Repository) => void
}) {
  const inputId = useId()
  const [file, setFile] = useState<File | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  function handleFile(event: ChangeEvent<HTMLInputElement>) {
    setError(null)
    const chosen = event.target.files?.[0] ?? null
    // Checked here so an obviously oversized file is not uploaded at all; the
    // server enforces the same limit, because this check is only a courtesy.
    if (chosen && chosen.size > MAX_UPLOAD_MB * 1024 * 1024) {
      setFile(null)
      setError(`That file is larger than the ${MAX_UPLOAD_MB} MB limit.`)
      return
    }
    setFile(chosen)
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!file) return
    // Captured before the await: React has detached the event by the time the
    // upload resolves, and `event.currentTarget` would be null.
    const form = event.currentTarget
    setError(null)
    setBusy(true)
    try {
      onConnected(await repositoryService.upload(projectId, file))
      setFile(null)
      form.reset()
    } catch (caught: unknown) {
      setError(toApiError(caught).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="repository-form" onSubmit={handleSubmit} noValidate>
      <FormField
        id={inputId}
        label="Zip archive"
        hint={`Up to ${MAX_UPLOAD_MB} MB. node_modules, .git and build folders are skipped.`}
        error={error ?? undefined}
      >
        <input
          id={inputId}
          className="input"
          type="file"
          accept=".zip,application/zip"
          onChange={handleFile}
          disabled={busy}
        />
      </FormField>
      <div className="form-actions">
        <button className="button button--primary" type="submit" disabled={!file || busy}>
          {busy ? 'Ingesting…' : 'Upload and ingest'}
        </button>
        {busy && <span className="form-actions__note">Reading and indexing the archive…</span>}
      </div>
    </form>
  )
}

function GitForm({
  projectId,
  defaultBranch,
  onConnected,
}: {
  projectId: number
  defaultBranch: string
  onConnected: (repository: Repository) => void
}) {
  const urlId = useId()
  const branchId = useId()
  const [url, setUrl] = useState('')
  const [branch, setBranch] = useState(defaultBranch)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)
    setBusy(true)
    try {
      onConnected(
        await repositoryService.connectGit(projectId, {
          repository_url: url.trim(),
          branch: branch.trim() || null,
        }),
      )
      setUrl('')
    } catch (caught: unknown) {
      setError(toApiError(caught).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="repository-form" onSubmit={handleSubmit} noValidate>
      <FormField
        id={urlId}
        label="Public Git URL"
        hint="https:// only. Private repositories need credentials, so upload a zip instead."
        error={error ?? undefined}
      >
        <input
          id={urlId}
          className="input"
          type="url"
          placeholder="https://github.com/owner/project"
          value={url}
          maxLength={500}
          onChange={(event) => setUrl(event.target.value)}
          disabled={busy}
          required
        />
      </FormField>
      <FormField id={branchId} label="Branch">
        <input
          id={branchId}
          className="input"
          value={branch}
          maxLength={100}
          onChange={(event) => setBranch(event.target.value)}
          disabled={busy}
        />
      </FormField>
      <div className="form-actions">
        <button className="button button--primary" type="submit" disabled={!url.trim() || busy}>
          {busy ? 'Cloning…' : 'Clone repository'}
        </button>
        {busy && <span className="form-actions__note">Cloning a single commit…</span>}
      </div>
    </form>
  )
}

function RepositoryCard({
  repository,
  onDeleted,
}: {
  repository: Repository
  onDeleted: () => void
}) {
  const [error, setError] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)
  // Kept locally so the panel flips from "never analysed" to "last analysed"
  // without re-fetching the whole repository list.
  const [analyzedAt, setAnalyzedAt] = useState<string | null>(repository.analyzed_at)
  const shares = toLanguageShares(repository.language_breakdown)

  async function handleDelete() {
    setError(null)
    setDeleting(true)
    try {
      await repositoryService.remove(repository.id)
      onDeleted()
    } catch (caught: unknown) {
      setError(toApiError(caught).message)
      setDeleting(false)
    }
  }

  return (
    <li className="repository-card">
      <div className="repository-card__header">
        <div>
          <p className="repository-card__origin" title={repository.origin}>
            {repository.origin}
          </p>
          <p className="repository-card__meta">
            {repository.source === 'GIT' ? 'Cloned' : 'Uploaded'} ·{' '}
            {formatDateTime(repository.ingested_at ?? repository.created_at)}
          </p>
        </div>
        <StatusBadge
          tone={STATUS_TONE[repository.status]}
          label={STATUS_LABEL[repository.status]}
        />
      </div>

      {repository.status === 'FAILED' ? (
        <p className="repository-card__error" role="alert">
          {repository.error_message ?? 'Ingestion failed.'}
        </p>
      ) : (
        <>
          <dl className="repository-card__facts">
            <div>
              <dt>Files</dt>
              <dd>{repository.file_count}</dd>
            </div>
            <div>
              <dt>Size</dt>
              <dd>{formatBytes(repository.total_bytes)}</dd>
            </div>
            <div>
              <dt>Language</dt>
              <dd>{repository.primary_language ?? 'Not detected'}</dd>
            </div>
            <div>
              <dt>Branch</dt>
              <dd>{repository.branch ?? EMPTY_VALUE}</dd>
            </div>
            <div>
              <dt>Commit</dt>
              <dd>
                <code>{formatCommit(repository.commit_hash)}</code>
              </dd>
            </div>
          </dl>

          {shares.length > 0 && (
            <>
              {/* The bar is decoration; the legend below it carries the same
                  information as text, so the bar is hidden from screen readers
                  rather than read out twice. */}
              <div className="language-bar" aria-hidden="true">
                {shares.slice(0, 5).map((share) => (
                  <span
                    key={share.language}
                    className="language-bar__segment"
                    style={{ width: `${share.percent}%` }}
                    title={`${share.language} — ${formatBytes(share.bytes)}`}
                  />
                ))}
              </div>
              <ul className="language-legend">
                {shares.slice(0, 5).map((share) => (
                  <li key={share.language}>
                    {share.language} {share.percent.toFixed(0)}% ({formatBytes(share.bytes)})
                  </li>
                ))}
              </ul>
            </>
          )}
        </>
      )}

      {repository.status === 'READY' && (
        <FindingsPanel
          repositoryId={repository.id}
          analyzedAt={analyzedAt}
          onAnalyzed={(summary) => setAnalyzedAt(summary.analyzed_at)}
        />
      )}

      {error && (
        <p className="repository-card__error" role="alert">
          {error}
        </p>
      )}

      <div className="repository-card__actions">
        <button
          type="button"
          className="button button--danger button--small"
          onClick={() => void handleDelete()}
          disabled={deleting}
        >
          {deleting ? 'Removing…' : 'Remove'}
        </button>
      </div>
    </li>
  )
}
