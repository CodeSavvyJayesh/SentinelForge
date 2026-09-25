import { useState } from 'react'
import { Link } from 'react-router-dom'

import { EmptyState } from '../components/EmptyState'
import { ErrorState } from '../components/ErrorState'
import { LoadingState } from '../components/LoadingState'
import { useProjects } from '../hooks/useProjects'
import type { Project } from '../types/project'
import { EMPTY_VALUE, formatDateTime } from '../utils/format'

export function ProjectsPage() {
  const [search, setSearch] = useState('')
  const { state, reload } = useProjects({ search })

  return (
    <section className="page" aria-labelledby="projects-title">
      <div className="page__header">
        <div>
          <h1 id="projects-title">Projects</h1>
          <p className="page__subtitle">
            Each project is a codebase you scan. Only you can see your projects.
          </p>
        </div>
        <Link className="button button--primary" to="/projects/new">
          New project
        </Link>
      </div>

      <div className="toolbar">
        <label className="visually-hidden" htmlFor="project-search">
          Search projects by name
        </label>
        <input
          id="project-search"
          className="input input--search"
          type="search"
          placeholder="Search by name…"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
      </div>

      {state.status === 'loading' && <LoadingState label="Loading projects…" />}

      {state.status === 'error' && (
        <ErrorState
          title="Could not load projects"
          message={state.error.message}
          code={state.error.code}
          requestId={state.error.requestId}
          onRetry={reload}
        />
      )}

      {state.status === 'success' &&
        (state.data.items.length === 0 ? (
          <EmptyState
            title={search ? 'No matching projects' : 'No projects yet'}
            message={
              search
                ? `Nothing matches "${search}".`
                : 'Create your first project to start scanning a codebase.'
            }
            action={
              !search && (
                <Link className="button button--primary" to="/projects/new">
                  Create project
                </Link>
              )
            }
          />
        ) : (
          <ProjectTable projects={state.data.items} total={state.data.total} />
        ))}
    </section>
  )
}

function ProjectTable({ projects, total }: { projects: Project[]; total: number }) {
  return (
    <div className="panel">
      <div className="panel__summary">
        <h2 className="panel__title">Your projects</h2>
        <p>
          {total} {total === 1 ? 'project' : 'projects'}
        </p>
      </div>
      <table className="checks">
        <caption className="visually-hidden">Your projects</caption>
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Repository</th>
            <th scope="col">Branch</th>
            <th scope="col">Language</th>
            <th scope="col">Created</th>
          </tr>
        </thead>
        <tbody>
          {projects.map((project) => (
            <tr key={project.id}>
              <th scope="row">
                <Link className="link" to={`/projects/${project.id}`}>
                  {project.name}
                </Link>
              </th>
              <td className="cell--truncate">{project.repository_url ?? EMPTY_VALUE}</td>
              <td>
                <code>{project.default_branch}</code>
              </td>
              <td>{project.language ?? EMPTY_VALUE}</td>
              <td>{formatDateTime(project.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
