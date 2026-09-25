import type { ReactNode } from 'react'
import { NavLink } from 'react-router-dom'

import { useAuth } from '../hooks/useAuth'

interface AppLayoutProps {
  children: ReactNode
}

export function AppLayout({ children }: AppLayoutProps) {
  const { user, logout } = useAuth()

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <header className="topbar">
        <NavLink className="brand" to="/projects">
          <svg className="brand__mark" viewBox="0 0 32 32" aria-hidden="true" focusable="false">
            <path
              d="M16 2 4 6.5v8.2c0 7.4 5.1 13.4 12 15.3 6.9-1.9 12-7.9 12-15.3V6.5z"
              fill="currentColor"
            />
            <path
              d="m10.5 16 4 4 7-8"
              fill="none"
              stroke="var(--color-bg)"
              strokeWidth="2.6"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          <span className="brand__name">SentinelForge</span>
        </NavLink>

        <nav aria-label="Primary">
          <ul className="nav">
            <li>
              <NavLink className="nav__link" to="/projects">
                Projects
              </NavLink>
            </li>
            <li>
              <NavLink className="nav__link" to="/status">
                System status
              </NavLink>
            </li>
            {user?.role === 'ADMIN' && (
              <li>
                <NavLink className="nav__link" to="/users">
                  Accounts
                </NavLink>
              </li>
            )}
          </ul>
        </nav>

        {user && (
          <div className="topbar__user">
            <span className="topbar__username">{user.username}</span>
            <span className={`role-tag role-tag--${user.role.toLowerCase()}`}>{user.role}</span>
            <button type="button" className="button button--quiet" onClick={() => void logout()}>
              Sign out
            </button>
          </div>
        )}
      </header>
      <main id="main-content" className="content">
        {children}
      </main>
    </div>
  )
}
