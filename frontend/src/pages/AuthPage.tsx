import { useState } from 'react'

import { LoginPage } from './LoginPage'
import { RegisterPage } from './RegisterPage'

/** Sign-in / sign-up screen shown while nobody is authenticated. */
export function AuthPage() {
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [notice, setNotice] = useState<string | null>(null)

  if (mode === 'register') {
    return (
      <div className="auth-screen">
        <RegisterPage
          onRegistered={(username) => {
            setNotice(`Account "${username}" created. You can sign in now.`)
            setMode('login')
          }}
          onSwitchToLogin={() => {
            setNotice(null)
            setMode('login')
          }}
        />
      </div>
    )
  }

  return (
    <div className="auth-screen">
      <LoginPage notice={notice} onSwitchToRegister={() => setMode('register')} />
    </div>
  )
}
