import type { ApiErrorEnvelope, ApiResult } from '../types/api'
import { readCookie } from '../utils/cookies'

export const CSRF_COOKIE_NAME = 'sf_csrf'
export const CSRF_HEADER_NAME = 'X-CSRF-Token'

/** Error codes produced by the client itself (the backend never sends these). */
export const ClientErrorCode = {
  NOT_CONFIGURED: 'NOT_CONFIGURED',
  NETWORK_ERROR: 'NETWORK_ERROR',
  TIMEOUT: 'TIMEOUT',
  INVALID_RESPONSE: 'INVALID_RESPONSE',
  HTTP_ERROR: 'HTTP_ERROR',
  UNKNOWN_ERROR: 'UNKNOWN_ERROR',
} as const

export interface ApiErrorInit {
  status: number
  code: string
  message: string
  details?: unknown
  requestId?: string | null
}

/** Every failed API call surfaces as an ApiError with a stable `code`. */
export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly details: unknown
  readonly requestId: string | null

  constructor(init: ApiErrorInit) {
    super(init.message)
    this.name = 'ApiError'
    this.status = init.status
    this.code = init.code
    this.details = init.details ?? null
    this.requestId = init.requestId ?? null
  }
}

export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error
  return new ApiError({
    status: 0,
    code: ClientErrorCode.UNKNOWN_ERROR,
    message: 'An unexpected client error occurred',
  })
}

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'

export interface RequestOptions {
  method?: HttpMethod
  body?: unknown
  signal?: AbortSignal
  timeoutMs?: number
  /** Non-2xx statuses whose body should be returned instead of thrown (e.g. 503 health). */
  acceptStatuses?: readonly number[]
  /** Attach the in-memory access token as `Authorization: Bearer ...`. */
  auth?: boolean
  /** Send cookies (needed by /auth/refresh and /auth/logout). */
  withCredentials?: boolean
  /** Echo the CSRF cookie in a header (double-submit check). */
  csrf?: boolean
  /** Internal: prevents an endless refresh loop. */
  retryOnUnauthorized?: boolean
}

export interface ApiClient {
  request<T>(path: string, options?: RequestOptions): Promise<ApiResult<T>>
}

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>

export interface ApiClientConfig {
  baseUrl: string | null
  fetchImpl?: FetchLike
  defaultTimeoutMs?: number
  /** Supplies the current access token (kept in memory, never in storage). */
  getAccessToken?: () => string | null
  /** Called once when an authenticated request gets 401; return true if a new
   *  token was obtained, and the request is retried. */
  onUnauthorized?: () => Promise<boolean>
  /** Reads the CSRF cookie; overridable in tests. */
  readCsrfToken?: () => string | null
}

const REQUEST_ID_HEADER = 'X-Request-ID'
const DEFAULT_TIMEOUT_MS = 10_000

function isErrorEnvelope(value: unknown): value is ApiErrorEnvelope {
  if (typeof value !== 'object' || value === null || !('error' in value)) return false
  const error = (value as { error: unknown }).error
  return (
    typeof error === 'object' &&
    error !== null &&
    typeof (error as { code?: unknown }).code === 'string' &&
    typeof (error as { message?: unknown }).message === 'string'
  )
}

function joinUrl(baseUrl: string, path: string): string {
  return `${baseUrl}${path.startsWith('/') ? path : `/${path}`}`
}

export function createApiClient({
  baseUrl,
  // Wrapped so `fetch` is never invoked with a foreign `this` ("Illegal invocation").
  fetchImpl = (input, init) => fetch(input, init),
  defaultTimeoutMs = DEFAULT_TIMEOUT_MS,
  getAccessToken = () => null,
  onUnauthorized,
  readCsrfToken = () => readCookie(CSRF_COOKIE_NAME),
}: ApiClientConfig): ApiClient {
  async function request<T>(path: string, options: RequestOptions = {}): Promise<ApiResult<T>> {
    if (!baseUrl) {
      throw new ApiError({
        status: 0,
        code: ClientErrorCode.NOT_CONFIGURED,
        message: 'VITE_API_BASE_URL is not configured. Copy frontend/.env.example to frontend/.env.',
      })
    }

    const {
      method = 'GET',
      body,
      signal,
      timeoutMs = defaultTimeoutMs,
      acceptStatuses = [],
      auth = false,
      withCredentials = false,
      csrf = false,
      retryOnUnauthorized = true,
    } = options

    const controller = new AbortController()
    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      controller.abort()
    }, timeoutMs)
    const forwardAbort = () => controller.abort()
    signal?.addEventListener('abort', forwardAbort, { once: true })

    // A file upload is sent as multipart form data, and the browser must set
    // `Content-Type` itself so it can add the multipart boundary.
    const isFormData = typeof FormData !== 'undefined' && body instanceof FormData

    const headers: Record<string, string> = { Accept: 'application/json' }
    if (body !== undefined && !isFormData) headers['Content-Type'] = 'application/json'
    if (auth) {
      const token = getAccessToken()
      if (token) headers.Authorization = `Bearer ${token}`
    }
    if (csrf) {
      const csrfToken = readCsrfToken()
      if (csrfToken) headers[CSRF_HEADER_NAME] = csrfToken
    }

    try {
      let response: Response
      let text: string
      try {
        response = await fetchImpl(joinUrl(baseUrl, path), {
          method,
          headers,
          body:
            body === undefined ? undefined : isFormData ? (body as FormData) : JSON.stringify(body),
          signal: controller.signal,
          credentials: withCredentials ? 'include' : 'same-origin',
        })
        text = await response.text()
      } catch (cause) {
        // A caller-initiated abort is not an error to display; let the caller ignore it.
        if (signal?.aborted) throw cause
        if (timedOut) {
          throw new ApiError({
            status: 0,
            code: ClientErrorCode.TIMEOUT,
            message: `The API did not respond within ${Math.round(timeoutMs / 1000)} seconds`,
          })
        }
        throw new ApiError({
          status: 0,
          code: ClientErrorCode.NETWORK_ERROR,
          message: 'Cannot reach the SentinelForge API. Is the backend running?',
        })
      }

      const requestId = response.headers.get(REQUEST_ID_HEADER)
      let payload: unknown = null
      if (text) {
        try {
          payload = JSON.parse(text)
        } catch {
          throw new ApiError({
            status: response.status,
            code: ClientErrorCode.INVALID_RESPONSE,
            message: 'The API returned a response that is not valid JSON',
            requestId,
          })
        }
      }

      if (response.ok || acceptStatuses.includes(response.status)) {
        return { data: payload as T, status: response.status, requestId }
      }

      // Expired access token: refresh once, then replay the original request.
      if (response.status === 401 && auth && retryOnUnauthorized && onUnauthorized) {
        const refreshed = await onUnauthorized()
        if (refreshed) {
          return request<T>(path, { ...options, retryOnUnauthorized: false })
        }
      }

      if (isErrorEnvelope(payload)) {
        throw new ApiError({
          status: response.status,
          code: payload.error.code,
          message: payload.error.message,
          details: payload.error.details,
          requestId: payload.error.request_id ?? requestId,
        })
      }

      throw new ApiError({
        status: response.status,
        code: ClientErrorCode.HTTP_ERROR,
        message: `Request failed with status ${response.status}`,
        requestId,
      })
    } finally {
      clearTimeout(timer)
      signal?.removeEventListener('abort', forwardAbort)
    }
  }

  return { request }
}
