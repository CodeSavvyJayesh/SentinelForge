import { useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'

import { FormField } from '../components/FormField'
import { projectService } from '../services/api'
import { toApiError } from '../services/apiClient'

const NAME_MAX = 120

export function ProjectCreatePage() {
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [repositoryUrl, setRepositoryUrl] = useState('')
  const [defaultBranch, setDefaultBranch] = useState('main')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      const project = await projectService.create({
        name: name.trim(),
        description: description.trim() || null,
        repository_url: repositoryUrl.trim() || null,
        default_branch: defaultBranch.trim() || 'main',
      })
      void navigate(`/projects/${project.id}`)
    } catch (caught: unknown) {
      setError(toApiError(caught).message)
      setSubmitting(false)
    }
  }

  return (
    <section className="page page--narrow" aria-labelledby="create-title">
      <div className="page__header">
        <div>
          <h1 id="create-title">New project</h1>
          <p className="page__subtitle">
            A project holds one codebase. The repository can be added later.
          </p>
        </div>
      </div>

      <form className="panel panel--form" onSubmit={handleSubmit} noValidate>
        <FormField id="project-name" label="Name" hint="Unique among your own projects.">
          <input
            id="project-name"
            className="input"
            type="text"
            maxLength={NAME_MAX}
            value={name}
            onChange={(event) => setName(event.target.value)}
            required
            autoFocus
          />
        </FormField>

        <FormField id="project-description" label="Description (optional)">
          <textarea
            id="project-description"
            className="input textarea"
            rows={3}
            maxLength={2000}
            value={description}
            onChange={(event) => setDescription(event.target.value)}
          />
        </FormField>

        <FormField
          id="project-repository"
          label="Repository URL (optional)"
          hint="https://… or git@… — used from Phase 4 onwards."
        >
          <input
            id="project-repository"
            className="input"
            type="text"
            value={repositoryUrl}
            onChange={(event) => setRepositoryUrl(event.target.value)}
          />
        </FormField>

        <FormField id="project-branch" label="Default branch">
          <input
            id="project-branch"
            className="input"
            type="text"
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
          <button
            className="button button--primary"
            type="submit"
            disabled={submitting || !name.trim()}
          >
            {submitting ? 'Creating…' : 'Create project'}
          </button>
          <Link className="button" to="/projects">
            Cancel
          </Link>
        </div>
      </form>
    </section>
  )
}
