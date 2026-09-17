import type { ReactNode } from 'react'

interface AppLayoutProps {
  children: ReactNode
}

export function AppLayout({ children }: AppLayoutProps) {
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <header className="topbar">
        <div className="brand">
          <svg className="brand__mark" viewBox="0 0 32 32" aria-hidden="true" focusable="false">
            <path d="M16 2 4 6.5v8.2c0 7.4 5.1 13.4 12 15.3 6.9-1.9 12-7.9 12-15.3V6.5z" fill="currentColor" />
            <path d="m10.5 16 4 4 7-8" fill="none" stroke="var(--color-bg)" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <span className="brand__name">SentinelForge</span>
        </div>
        <nav aria-label="Primary">
          <ul className="nav">
            <li>
              <a className="nav__link" aria-current="page" href="/">
                System status
              </a>
            </li>
          </ul>
        </nav>
      </header>
      <main id="main-content" className="content">
        {children}
      </main>
    </div>
  )
}
