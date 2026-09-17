interface ErrorStateProps {
  title: string
  message: string
  code?: string
  requestId?: string | null
  onRetry?: () => void
}

export function ErrorState({ title, message, code, requestId, onRetry }: ErrorStateProps) {
  return (
    <div className="state state--error" role="alert">
      <div className="state__body">
        <h2 className="state__title">{title}</h2>
        <p className="state__message">{message}</p>
        {(code || requestId) && (
          <dl className="meta-list">
            {code && (
              <div>
                <dt>Error code</dt>
                <dd>
                  <code>{code}</code>
                </dd>
              </div>
            )}
            {requestId && (
              <div>
                <dt>Request ID</dt>
                <dd>
                  <code>{requestId}</code>
                </dd>
              </div>
            )}
          </dl>
        )}
      </div>
      {onRetry && (
        <button type="button" className="button" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  )
}
