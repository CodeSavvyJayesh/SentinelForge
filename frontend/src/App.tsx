import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'

import { LoadingState } from './components/LoadingState'
import { AuthProvider } from './context/AuthProvider'
import { useAuth } from './hooks/useAuth'
import { AppLayout } from './layouts/AppLayout'
import { AuthPage } from './pages/AuthPage'
import { ProjectCreatePage } from './pages/ProjectCreatePage'
import { ProjectDetailPage } from './pages/ProjectDetailPage'
import { ProjectsPage } from './pages/ProjectsPage'
import { SystemStatusPage } from './pages/SystemStatusPage'
import { UsersPage } from './pages/UsersPage'

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <AuthenticatedApp />
      </BrowserRouter>
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
      <Routes>
        <Route path="/" element={<Navigate to="/projects" replace />} />
        {/* Signing in from /login or /register leaves that path in the address
            bar; without these the user would land on "Page not found". */}
        <Route path="/login" element={<Navigate to="/projects" replace />} />
        <Route path="/register" element={<Navigate to="/projects" replace />} />
        <Route path="/projects" element={<ProjectsPage />} />
        <Route path="/projects/new" element={<ProjectCreatePage />} />
        <Route path="/projects/:projectId" element={<ProjectDetailPage />} />
        <Route path="/status" element={<SystemStatusPage />} />
        {/* Admin-only route: guarded here and again by the API. */}
        <Route
          path="/users"
          element={user?.role === 'ADMIN' ? <UsersPage /> : <Navigate to="/projects" replace />}
        />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </AppLayout>
  )
}

function NotFoundPage() {
  return (
    <section className="page">
      <h1>Page not found</h1>
      <p className="page__subtitle">That address does not exist in SentinelForge.</p>
    </section>
  )
}
