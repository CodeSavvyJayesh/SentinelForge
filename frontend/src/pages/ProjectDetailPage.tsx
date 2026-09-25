import { useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'

import { ErrorState } from '../components/ErrorState'
import { FormField } from '../components/FormField'
import { LoadingState } from '../components/LoadingState'
import { RepositoryPanel } from '../components/RepositoryPanel'
import { useProject } from '../hooks/useProject'
import { projectService } from '../services/api'
import { toApiError } from '../services/apiClient'
import type { Project } from '../types/project'
import { EMPTY_VALUE, formatDateTime } from '../utils/format'

export function ProjectDetailPage() {
  const { projectId } = useParams()
  const parsedId = Number(projectId)

  if (!Number.isInteger(parsedId) || parsedId <= 0) {
    return (
      <section className="page">
        <ErrorState title="Project not found" message="That project id is not valid." />
        <p>
          <Link className="link" to="/projects">
            Back to projects
          </Link>
        </p>
      </section>
    )
  }

  return <ProjectDetail projectId={parsedId} />
}

function ProjectDetail({ projectId }: { projectId: number }) {
  const { state, reload, setProject } = useProject(projectId)

  if (state.status === 'loading') return <LoadingState label="Loading project…" />

  if (state.status === 'error') {
    const notFound = state.error.status === 404
    return (
      <section className="page">
        <ErrorState
          title={notFound ? 'Project not found' : 'Could not load project'}
          // A project owned by someone else answers 404 as well: the API never
          // confirms that another user's project exists.
          message={
            notFound
              ? 'This project does not exist, or it is not yours.'
              : state.error.message
          }
          code={state.error.code}
          requestId={state.error.requestId}
          onRetry={notFound ? undefined : reload}
        />
        <p className="page__back">
          <Link className="link" to="/projects">
            Back to projects
          </Link>
        </p>
      </section>
    )
  }

  return <ProjectView project={state.project} onUpdated={setProject} />
}

function ProjectView({
  project,
  onUpdated,
}: {
  project: Project
  onUpdated: (project: Project) => void
}) {
  const navigate = useNavigate()
  const [editing, setEditing] = useState(false)

  return (
    <section className="page" aria-labelledby="project-title">
      <div className="page__header">
        <div>
          <p className="page__breadcrumb">
            <Link className="link" to="/projects">
              Projects
            </Link>{' '}
            / {project.name}
          </p>
          <h1 id="project-title">{project.name}</h1>
          <p className="page__subtitle">{project.description ?? 'No description yet.'}</p>
        </div>
        <button type="button" className="button" onClick={() => setEditing((value) => !value)}>
          {editing ? 'Cancel edit' : 'Edit'}
        </button>
      </div>

      {editing ? (
        <EditProjectForm
          project={project}
          onSaved={(updated) => {
            onUpdated(updated)
            setEditing(false)
          }}
        />
      ) : (
        <div className="panel">
          <dl className="detail-list">
            <div>
              <dt>Repository</dt>
              <dd>{project.repository_url ?? EMPTY_VALUE}</dd>
            </div>
            <div>
              <dt>Default branch</dt>
              <dd>
                <code>{project.default_branch}</code>
              </dd>
            </div>
            <div>
              <dt>Language</dt>
              <dd>{project.language ?? 'Detected per repository, below'}</dd>
            </div>
            <div>
              <dt>Created</dt>
              <dd>{formatDateTime(project.created_at)}</dd>
            </div>
            <div>
              <dt>Last updated</dt>
              <dd>{formatDateTime(project.updated_at)}</dd>
            </div>
          </dl>
        </div>
      )}

      <RepositoryPanel projectId={project.id} defaultBranch={project.default_branch} />

      <div className="panel panel--planned">
        <h2 className="panel__title">Scan history</h2>
        <p>
          Each repository above can be analysed now, and shows its current findings. Scheduled and
          background scans, with a history you can compare over time, arrive in Phase 6.
        </p>
      </div>

      <DeleteProject project={project} onDeleted={() => void navigate('/projects')} />
    </section>
  )
}

function EditProjectForm({
  project,
  onSaved,
}: {
  project: Project
  onSaved: (project: Project) => void
}) {
  const [name, setName] = useState(project.name)
  const [description, setDescription] = useState(project.description ?? '')
  const [repositoryUrl, setRepositoryUrl] = useState(project.repository_url ?? '')
  const [defaultBranch, setDefaultBranch] = useState(project.default_branch)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)
    setSaving(true)
    try {
      const updated = await projectService.update(project.id, {
        name: name.trim(),
        description: description.trim() || null,
        repository_url: repositoryUrl.trim() || null,
        default_branch: defaultBranch.trim() || 'main',
      })
      onSaved(updated)
    } catch (caught: unknown) {
      setError(toApiError(caught).message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <form className="panel panel--form" onSubmit={handleSubmit} noValidate>
      <FormField id="edit-name" label="Name">
        <input
          id="edit-name"
          className="input"
          value={name}
          maxLength={120}
          onChange={(event) => setName(event.target.value)}
          required
        />
      </FormField>
      <FormField id="edit-description" label="Description">
        <textarea
          id="edit-description"
          className="input textarea"
          rows={3}
          maxLength={2000}
          value={description}
          onChange={(event) => setDescription(event.target.value)}
        />
      </FormField>
      <FormField id="edit-repository" label="Repository URL">
        <input
          id="edit-repository"
          className="input"
          value={repositoryUrl}
          onChange={(event) => setRepositoryUrl(event.target.value)}
        />
      </FormField>
      <FormField id="edit-branch" label="Default branch">
        <input
          id="edit-branch"
          className="input"
          value={defaultBranch}
          onChange={(event) => setDefaultBranch(event.target.value)}
        />
      </FormField>

      {error && (
        <p className="auth-form__error" role="alert">
          {error}
        </p>
      )}

      <div className="form-actions">
        <button className="button button--primary" type="submit" disabled={saving || !name.trim()}>
          {saving ? 'Saving…' : 'Save changes'}
        </button>
      </div>
    </form>
  )
}

function DeleteProject({ project, onDeleted }: { project: Project; onDeleted: () => void }) {
  const [confirmation, setConfirmation] = useState('')
  const [open, setOpen] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)
  const canDelete = confirmation === project.name

  async function handleDelete() {
    setError(null)
    setDeleting(true)
    try {
      await projectService.remove(project.id)
      onDeleted()
    } catch (caught: unknown) {
      setError(toApiError(caught).message)
      setDeleting(false)
    }
  }

  return (
    <div className="panel panel--danger">
      <h2 className="panel__title">Delete project</h2>
      <p>Deleting removes the project permanently. This cannot be undone.</p>

      {open ? (
        <>
          <FormField
            id="delete-confirm"
            label={`Type "${project.name}" to confirm`}
            error={error ?? undefined}
          >
            <input
              id="delete-confirm"
              className="input"
              value={confirmation}
              onChange={(event) => setConfirmation(event.target.value)}
              autoComplete="off"
            />
          </FormField>
          <div className="form-actions">
            <button
              type="button"
              className="button button--danger"
              disabled={!canDelete || deleting}
              onClick={() => void handleDelete()}
            >
              {deleting ? 'Deleting…' : 'Delete permanently'}
            </button>
            <button type="button" className="button" onClick={() => setOpen(false)}>
              Cancel
            </button>
          </div>
        </>
      ) : (
        <button type="button" className="button button--danger" onClick={() => setOpen(true)}>
          Delete project
        </button>
      )}
    </div>
  )
}
