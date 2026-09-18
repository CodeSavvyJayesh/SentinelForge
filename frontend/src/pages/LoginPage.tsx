import { useState } from 'react'
import type { FormEvent } from 'react'

import { FormField } from '../components/FormField'
import { useAuth } from '../hooks/useAuth'
import { toApiError } from '../services/apiClient'

interface LoginPageProps {
  onSwitchToRegister: () => void
  notice?: string | null
}

export function LoginPage({ onSwitchToRegister, notice }: LoginPageProps) {
  const { login } = useAuth()
  const [identifier, setIdentifier] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await login({ identifier: identifier.trim(), password })
    } catch (caught: unknown) {
      setError(toApiError(caught).message)
      setSubmitting(false)
    }
  }

  return (
    <form className="auth-form" onSubmit={handleSubmit} noValidate>
      <h1 className="auth-form__title">Sign in</h1>
      <p className="auth-form__subtitle">Use your SentinelForge account.</p>

      {notice && <p className="auth-form__notice">{notice}</p>}

      <FormField id="identifier" label="Email or username">
        <input
          id="identifier"
          className="input"
          type="text"
          autoComplete="username"
          value={identifier}
          onChange={(event) => setIdentifier(event.target.value)}
          required
        />
      </FormField>

      <FormField id="password" label="Password">
        <input
          id="password"
          className="input"
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          required
        />
      </FormField>

      {error && (
        <p className="auth-form__error" role="alert">
          {error}
        </p>
      )}

      <button className="button button--primary" type="submit" disabled={submitting}>
        {submitting ? 'Signing in…' : 'Sign in'}
      </button>

      <p className="auth-form__switch">
        No account yet?{' '}
        <button type="button" className="link-button" onClick={onSwitchToRegister}>
          Create one
        </button>
      </p>
    </form>
  )
}
