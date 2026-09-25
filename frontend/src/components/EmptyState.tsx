import type { ReactNode } from 'react'

interface EmptyStateProps {
  title: string
  message: string
  action?: ReactNode
}

/** Shown when a list is genuinely empty — never a placeholder row of fake data. */
export function EmptyState({ title, message, action }: EmptyStateProps) {
  return (
    <div className="state state--empty">
      <div className="state__body">
        <h2 className="state__title">{title}</h2>
        <p className="state__message">{message}</p>
      </div>
      {action}
    </div>
  )
}
