import { useState } from 'react'
import type { FormEvent } from 'react'

import { FormField } from '../components/FormField'
import { useAuth } from '../hooks/useAuth'
import { toApiError } from '../services/apiClient'

/** Must match PASSWORD_MIN_LENGTH in the backend settings. */
export const PASSWORD_MIN_LENGTH = 12

interface RegisterPageProps {
  onRegistered: (username: string) => void
  onSwitchToLogin: () => void
}

export function RegisterPage({ onRegistered, onSwitchToLogin }: RegisterPageProps) {
  const { register } = useAuth()
  const [email, setEmail] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  const passwordTooShort = password.length > 0 && password.length < PASSWORD_MIN_LENGTH
  const mismatch = confirmation.length > 0 && confirmation !== password

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (passwordTooShort || mismatch) return
    setError(null)
    setSubmitting(true)
    try {
      const user = await register({ email: email.trim(), username: username.trim(), password })
      onRegistered(user.username)
    } catch (caught: unknown) {
      setError(toApiError(caught).message)
      setSubmitting(false)
    }
  }

  return (
    <form className="auth-form" onSubmit={handleSubmit} noValidate>
      <h1 className="auth-form__title">Create account</h1>
      <p className="auth-form__subtitle">The first account created becomes the administrator.</p>

      <FormField id="email" label="Email">
        <input
          id="email"
          className="input"
          type="email"
          autoComplete="email"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          required
        />
      </FormField>

      <FormField id="username" label="Username" hint="Letters, digits, dot, underscore, hyphen.">
        <input
          id="username"
          className="input"
          type="text"
          autoComplete="username"
          minLength={3}
          value={username}
          onChange={(event) => setUsername(event.target.value)}
          required
        />
      </FormField>

      <FormField
        id="new-password"
        label="Password"
        hint={`At least ${PASSWORD_MIN_LENGTH} characters. A passphrase works well.`}
        error={passwordTooShort ? `Use at least ${PASSWORD_MIN_LENGTH} characters.` : undefined}
      >
        <input
          id="new-password"
          className="input"
          type="password"
          autoComplete="new-password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          required
        />
      </FormField>

      <FormField
        id="confirm-password"
        label="Confirm password"
        error={mismatch ? 'Passwords do not match.' : undefined}
      >
        <input
          id="confirm-password"
          className="input"
          type="password"
          autoComplete="new-password"
          value={confirmation}
          onChange={(event) => setConfirmation(event.target.value)}
          required
        />
      </FormField>

      {error && (
        <p className="auth-form__error" role="alert">
          {error}
        </p>
      )}

      <button
        className="button button--primary"
        type="submit"
        disabled={submitting || passwordTooShort || mismatch}
      >
        {submitting ? 'Creating account…' : 'Create account'}
      </button>

      <p className="auth-form__switch">
        Already registered?{' '}
        <button type="button" className="link-button" onClick={onSwitchToLogin}>
          Sign in
        </button>
      </p>
    </form>
  )
}
