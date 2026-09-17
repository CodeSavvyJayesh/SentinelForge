/** Mirrors backend/app/schemas/health.py */
export type ComponentStatus = 'up' | 'down'
export type OverallStatus = 'healthy' | 'unhealthy'

export interface DependencyCheck {
  status: ComponentStatus
  latency_ms: number | null
  message: string | null
}

export interface HealthResponse {
  status: OverallStatus
  version: string
  checked_at: string
  checks: {
    database: DependencyCheck
  }
}
