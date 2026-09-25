import { appConfig } from '../config/env'
import { createAnalysisService } from './analysisService'
import { createApiClient } from './apiClient'
import { createAuthService } from './authService'
import { createHealthService } from './healthService'
import { createProjectService } from './projectService'
import { createRepositoryService } from './repositoryService'
import { createUserService } from './userService'
import { tokenStore } from './tokenStore'

/**
 * Wiring for the whole app: one API client, one service per feature.
 *
 * `onUnauthorized` lets any authenticated request recover from an expired
 * access token by refreshing once, transparently, before it fails.
 */
export const apiClient = createApiClient({
  baseUrl: appConfig.apiBaseUrl,
  getAccessToken: () => tokenStore.get(),
  onUnauthorized: async () => {
    try {
      const refreshed = await authService.refresh()
      tokenStore.set(refreshed.access_token)
      return true
    } catch {
      tokenStore.clear()
      return false
    }
  },
})

export const authService = createAuthService(apiClient)
export const healthService = createHealthService(apiClient)
export const userService = createUserService(apiClient)
export const projectService = createProjectService(apiClient)
export const repositoryService = createRepositoryService(apiClient)
export const analysisService = createAnalysisService(apiClient)
