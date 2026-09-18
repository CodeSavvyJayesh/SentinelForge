import { AppLayout } from './layouts/AppLayout'
import { LoadingState } from './components/LoadingState'
import { AuthProvider } from './context/AuthProvider'
import { useAuth } from './hooks/useAuth'
import { AuthPage } from './pages/AuthPage'
import { SystemStatusPage } from './pages/SystemStatusPage'
import { UsersPanel } from './pages/UsersPanel'

export default function App() {
  return (
    <AuthProvider>
      <AuthenticatedApp />
    </AuthProvider>
  )
}

function AuthenticatedApp() {
  const { status, user, error } = useAuth()

  if (status === 'loading') {
    return (
      <div className="auth-screen">
        <LoadingState label="Restoring your session…" />
      </div>
    )
  }

  if (status === 'anonymous') {
    return (
      <>
        {error && (
          <p className="auth-screen__banner" role="alert">
            {error.message}
          </p>
        )}
        <AuthPage />
      </>
    )
  }

  return (
    <AppLayout>
      <SystemStatusPage />
      {user?.role === 'ADMIN' && (
        <section className="page" aria-labelledby="accounts-title">
          <div className="page__header">
            <div>
              <h2 id="accounts-title">Administration</h2>
              <p className="page__subtitle">Visible to administrators only.</p>
            </div>
          </div>
          <UsersPanel />
        </section>
      )}
    </AppLayout>
  )
}
