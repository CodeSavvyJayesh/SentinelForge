import { appConfig } from '../config/env'
import { createApiClient } from './apiClient'

/** The single API client instance used by all feature services. */
export const apiClient = createApiClient({ baseUrl: appConfig.apiBaseUrl })
