import { UsersPanel } from './UsersPanel'

/** Admin-only screen. The API enforces the role as well; this is convenience. */
export function UsersPage() {
  return (
    <section className="page" aria-labelledby="accounts-title">
      <div className="page__header">
        <div>
          <h1 id="accounts-title">Accounts</h1>
          <p className="page__subtitle">Visible to administrators only.</p>
        </div>
      </div>
      <UsersPanel />
    </section>
  )
}
