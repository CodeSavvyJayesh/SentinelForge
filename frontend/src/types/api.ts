/** Standard error envelope returned by every SentinelForge API error. */
export interface ApiErrorBody {
  code: string
  message: string
  details: unknown
  request_id: string | null
}

export interface ApiErrorEnvelope {
  error: ApiErrorBody
}

/** A successful (or explicitly accepted) API response. */
export interface ApiResult<T> {
  data: T
  status: number
  requestId: string | null
}
