export type StatusTone = 'ok' | 'fail' | 'pending'

interface StatusBadgeProps {
  tone: StatusTone
  label: string
}

/** Status is conveyed by icon shape AND text, never by colour alone. */
export function StatusBadge({ tone, label }: StatusBadgeProps) {
  return (
    <span className={`status-badge status-badge--${tone}`}>
      <StatusIcon tone={tone} />
      <span>{label}</span>
    </span>
  )
}

function StatusIcon({ tone }: { tone: StatusTone }) {
  const common = {
    width: 14,
    height: 14,
    viewBox: '0 0 16 16',
    'aria-hidden': true,
    focusable: false,
  } as const

  if (tone === 'ok') {
    return (
      <svg {...common}>
        <circle cx="8" cy="8" r="7" fill="currentColor" opacity="0.2" />
        <path d="m4.8 8.2 2.1 2.1 4.3-4.6" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    )
  }
  if (tone === 'fail') {
    return (
      <svg {...common}>
        <path d="M8 1.5 15 14H1z" fill="currentColor" opacity="0.2" />
        <path d="M8 6v3.6M8 11.6v.1" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
      </svg>
    )
  }
  return (
    <svg {...common}>
      <circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" strokeWidth="1.8" strokeDasharray="3 2.4" />
    </svg>
  )
}
