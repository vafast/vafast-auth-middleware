/**
 * @vafast/auth-middleware
 * 
 * Vafast 认证中间件 - 完整的 JWT/API Key 验证解决方案
 * 
 * 特点：
 * - 开箱即用：内置 auth-server 客户端，无需额外依赖
 * - 硬认证模式：验证失败直接返回 401，需要认证就加中间件，不需要就不加
 * - 支持 JWT 和 API Key 两种认证方式
 * - 可选依赖注入：高级用户可自定义验证函数
 */

import { defineMiddleware, withContext, err } from 'vafast'

// ============ 通用类型定义 ============

/** 用户信息 */
export interface UserInfo {
  id: string
  appId: string
  email?: string
  phone?: string
  avatar?: string
  status?: string
  roleId?: string
  nickname?: string
  verified?: boolean
  [key: string]: unknown
}

/** API Key 信息 */
export interface ApiKeyInfo {
  id: string
  name: string
  appId: string
  userId: string
  status: string
  permissions?: string[]
  [key: string]: unknown
}

/** App 信息 */
export interface AppInfo {
  id: string
  name: string
  status: string
  [key: string]: unknown
}

/** API 响应结果 */
export interface ApiResult<T> {
  data?: T
  error?: { code: number; message: string }
}

// ============ Auth Client 配置 ============

/** Auth 客户端配置 */
export interface AuthClientConfig {
  /** auth-server 基础 URL，如 http://localhost:9003。不传则读取 AUTH_API_BASE_URL 环境变量 */
  baseUrl?: string
  /** 服务间通信使用的 API Key ID。不传则读取 AUTH_SERVICE_API_KEY_ID 环境变量 */
  apiKeyId?: string
  /** 服务间通信使用的 API Key Secret。不传则读取 AUTH_SERVICE_API_KEY_SECRET 环境变量 */
  apiKeySecret?: string
  /** 请求超时时间（毫秒），默认 5000 */
  timeout?: number
}

/** 从环境变量获取配置值 */
function getEnvConfig() {
  return {
    baseUrl: process.env.AUTH_API_BASE_URL,
    apiKeyId: process.env.AUTH_SERVICE_API_KEY_ID,
    apiKeySecret: process.env.AUTH_SERVICE_API_KEY_SECRET,
    timeout: process.env.AUTH_API_TIMEOUT ? Number(process.env.AUTH_API_TIMEOUT) : undefined,
  }
}

// ============ 内置 Auth Client ============

/**
 * 创建 Auth 客户端
 * 
 * 内置的 auth-server 客户端，使用原生 fetch 实现
 * 
 * @param config 可选配置，不传则从环境变量读取
 * 
 * @example
 * ```typescript
 * // 方式1：无参数，自动读取环境变量
 * const client = createAuthClient()
 * 
 * // 方式2：手动配置
 * const client = createAuthClient({ baseUrl: 'http://localhost:9003' })
 * ```
 */
export function createAuthClient(config?: AuthClientConfig) {
  const env = getEnvConfig()
  const baseUrl = config?.baseUrl || env.baseUrl

  if (!baseUrl) {
    throw new Error('缺少 baseUrl 配置。请传入 baseUrl 参数或设置 AUTH_API_BASE_URL 环境变量')
  }

  const apiKeyId = config?.apiKeyId ?? env.apiKeyId ?? ''
  const apiKeySecret = config?.apiKeySecret ?? env.apiKeySecret ?? ''
  const timeout = config?.timeout ?? env.timeout ?? 5000

  // 构建请求头
  function buildHeaders(userId?: string): Record<string, string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    }

    // 服务间通信认证
    if (apiKeyId && apiKeySecret) {
      headers['authorization'] = `Bearer ${apiKeyId}:${apiKeySecret}`
    }

    // 代理用户请求时传递用户 ID
    if (userId) {
      headers['x-user-id'] = userId
    }

    return headers
  }

  // 带超时的 fetch
  async function fetchWithTimeout(
    url: string,
    options: RequestInit
  ): Promise<Response> {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), timeout)

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
      })
      return response
    } finally {
      clearTimeout(timeoutId)
    }
  }

  // 调用 auth-server API（原始格式：HTTP 状态码判断成功/失败）
  async function callAuthApi<T>(
    path: string,
    body: Record<string, unknown>,
    options?: { userId?: string }
  ): Promise<ApiResult<T>> {
    try {
      const response = await fetchWithTimeout(`${baseUrl}${path}`, {
        method: 'POST',
        headers: buildHeaders(options?.userId),
        body: JSON.stringify(body),
      })

      const data = await response.json()

      // 成功：HTTP 2xx，直接返回响应数据
      if (response.ok) {
        return { data: data as T }
      }

      // 失败：HTTP 4xx/5xx
      return {
        error: {
          code: data.code || response.status,
          message: data.message || '请求失败',
        },
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : '网络错误'
      return {
        error: { code: -1, message },
      }
    }
  }

  return {
    /**
     * 验证 JWT Token
     * 注意：使用独立的 /verifyJwt 路由，不需要 app-id header
     */
    async verifyJwt(token: string, appId?: string): Promise<ApiResult<UserInfo>> {
      return callAuthApi<UserInfo>('/authRestfulApi/verifyJwt', { token, appId })
    },

    /**
     * 验证 API Key
     * 注意：使用独立的 /verifyApiKey 路由，不需要 app-id header
     */
    async verifyApiKey(
      apiKeyId: string,
      secretKey: string
    ): Promise<ApiResult<{ userInfo: UserInfo; apiKey: ApiKeyInfo }>> {
      return callAuthApi<{ userInfo: UserInfo; apiKey: ApiKeyInfo }>(
        '/authRestfulApi/verifyApiKey',
        { apiKeyId, secretKey }
      )
    },

    /**
     * 验证应用
     */
    async verifyApp(
      appId: string
    ): Promise<ApiResult<{ valid: boolean; app?: AppInfo; message?: string }>> {
      return callAuthApi<{ valid: boolean; app?: AppInfo; message?: string }>(
        '/authRestfulApi/apps/verify',
        { appId }
      )
    },

    /**
     * 批量获取用户信息
     */
    async getUsersBatch(
      userIds: string[],
      options?: { userId?: string }
    ): Promise<ApiResult<UserInfo[]>> {
      return callAuthApi<UserInfo[]>(
        '/authRestfulApi/users/batch',
        { userIds },
        options
      )
    },

    /**
     * 搜索用户
     */
    async searchUsers(
      params: { keyword?: string; appId?: string; current?: number; pageSize?: number },
      options?: { userId?: string }
    ): Promise<ApiResult<{ list: UserInfo[]; total: number }>> {
      return callAuthApi<{ list: UserInfo[]; total: number }>(
        '/authRestfulApi/users/find',
        params,
        options
      )
    },

    /**
     * 获取用户统计
     */
    async getUsersStats(
      params: { appId?: string; startTime?: string; endTime?: string },
      options?: { userId?: string }
    ): Promise<ApiResult<{ total: number; new: number; active: number }>> {
      return callAuthApi<{ total: number; new: number; active: number }>(
        '/authRestfulApi/users/statistics',
        params,
        options
      )
    },
  }
}

/** Auth Client 类型 */
export type AuthClient = ReturnType<typeof createAuthClient>

// ============ 中间件选项 ============

/** 认证中间件选项：直接传配置、已创建的客户端，或不传（从环境变量读取） */
export type AuthMiddlewareOptions = AuthClientConfig | AuthClient | undefined

/** App 验证中间件选项 */
export interface ValidateAppOptions {
  /** 是否必须提供 app-id，默认 true */
  required?: boolean
  /** 是否调用 auth-server 验证 app-id 有效性，默认 true */
  verify?: boolean
}

// ============ 辅助函数 ============

/** 判断是否为 AuthClient 实例 */
function isAuthClient(obj: unknown): obj is AuthClient {
  return obj !== null && obj !== undefined && 'verifyJwt' in (obj as object) && typeof (obj as AuthClient).verifyJwt === 'function'
}

/** 获取或创建 AuthClient 实例 */
function getClient(options?: AuthMiddlewareOptions): AuthClient {
  if (!options) {
    return createAuthClient()
  }
  if (isAuthClient(options)) {
    return options
  }
  return createAuthClient(options)
}

// ============ JWT 认证中间件 ============

/**
 * JWT 认证中间件（硬认证）
 * 
 * 从请求头提取 JWT，调用 auth-server 验证，将用户信息注入上下文
 * 验证失败直接返回 401
 * 
 * @param options 可选配置，不传则从环境变量读取
 * 
 * @example
 * ```ts
 * // 方式1：无参数，自动读取环境变量
 * const jwtAuth = authenticateJwt()
 * 
 * // 方式2：手动配置
 * const jwtAuth = authenticateJwt({ baseUrl: 'http://localhost:9003' })
 * ```
 */
export function authenticateJwt(options?: AuthMiddlewareOptions) {
  const client = getClient(options)

  return defineMiddleware<{ userInfo: UserInfo }>(async (req, next) => {
    const authorization = req.headers.get('authorization')
    const appId = req.headers.get('app-id')

    // 无 authorization，返回 401
    if (!authorization || !authorization.startsWith('Bearer ')) {
      throw err('未提供认证信息', 401)
    }

    const jwtToken = authorization.slice(7)
    if (!jwtToken) {
      throw err('未提供认证信息', 401)
    }

    // 如果是 API Key 格式（包含冒号），不是 JWT
    if (jwtToken.includes(':')) {
      throw err('无效的 JWT Token', 401)
    }

    // 调用 auth-server API 验证 JWT
    const result = await client.verifyJwt(jwtToken, appId || undefined)

    if (!result.data) {
      throw err(result.error?.message || '认证失败', 401)
    }

    // 检查用户状态
    if (result.data.status === 'disabled') {
      throw err('账号已被禁用', 401)
    }
    if (result.data.status === 'deleted') {
      throw err('账号已被删除', 401)
    }

    const userInfo: UserInfo = {
      id: result.data.id,
      appId: result.data.appId || appId || '',
      email: result.data.email || '',
      phone: result.data.phone || '',
      avatar: result.data.avatar || '',
      status: result.data.status || 'normal',
      roleId: result.data.roleId || '',
      nickname: result.data.nickname,
      verified: result.data.verified,
    }
    return next({ userInfo })
  })
}

// ============ API Key 认证中间件 ============

/** API Key 认证上下文 */
export interface ApiKeyContext {
  userInfo?: UserInfo
  apiKey?: ApiKeyInfo
}

/**
 * API Key 认证中间件（硬认证）
 * 
 * 从请求头提取 API Key，调用 auth-server 验证，将用户信息和 API Key 信息注入上下文
 * 验证失败直接返回 401
 * 
 * @param options 可选配置，不传则从环境变量读取
 * 
 * @example
 * ```ts
 * // 方式1：无参数，自动读取环境变量
 * const apiKeyAuth = authenticateApiKey()
 * 
 * // 方式2：手动配置
 * const apiKeyAuth = authenticateApiKey({ baseUrl: 'http://localhost:9003' })
 * ```
 */
export function authenticateApiKey(options?: AuthMiddlewareOptions) {
  const client = getClient(options)

  return defineMiddleware<ApiKeyContext>(async (req, next) => {
    const authorization = req.headers.get('authorization')

    // 无 authorization，返回 401
    if (!authorization || !authorization.startsWith('Bearer ')) {
      throw err('未提供认证信息', 401)
    }

    const token = authorization.slice(7)
    if (!token) {
      throw err('未提供认证信息', 401)
    }

    // API Key 格式：apiKeyId:secretKey
    if (!token.includes(':')) {
      throw err('无效的 API Key 格式', 401)
    }

    const [apiKeyId, secretKey] = token.split(':')
    if (!apiKeyId || !secretKey) {
      throw err('无效的 API Key 格式', 401)
    }

    // 调用 auth-server API 验证 API Key
    const result = await client.verifyApiKey(apiKeyId, secretKey)

    if (!result.data) {
      throw err(result.error?.message || 'API Key 验证失败', 401)
    }

    return next({
      userInfo: result.data.userInfo,
      apiKey: result.data.apiKey,
    })
  })
}

// ============ 混合认证中间件 ============

/**
 * 混合认证中间件（硬认证）
 * 
 * 同时支持 JWT 和 API Key 认证，自动识别认证方式
 * 验证失败直接返回 401
 * 
 * @param options 可选配置，不传则从环境变量读取
 * 
 * @example
 * ```ts
 * // 方式1：无参数，自动读取环境变量
 * const auth = authenticate()
 * 
 * // 方式2：手动配置
 * const auth = authenticate({ baseUrl: 'http://localhost:9003' })
 * ```
 */
export function authenticate(options?: AuthMiddlewareOptions) {
  const client = getClient(options)

  return defineMiddleware<ApiKeyContext>(async (req, next) => {
    const authorization = req.headers.get('authorization')
    const appId = req.headers.get('app-id')

    // 无 authorization，返回 401
    if (!authorization || !authorization.startsWith('Bearer ')) {
      throw err('未提供认证信息', 401)
    }

    const token = authorization.slice(7)
    if (!token) {
      throw err('未提供认证信息', 401)
    }

    if (token.includes(':')) {
      // API Key
      const [apiKeyId, secretKey] = token.split(':')
      if (!apiKeyId || !secretKey) {
        throw err('无效的 API Key 格式', 401)
      }

      const result = await client.verifyApiKey(apiKeyId, secretKey)
      if (!result.data) {
        throw err(result.error?.message || 'API Key 验证失败', 401)
      }

      return next({ userInfo: result.data.userInfo, apiKey: result.data.apiKey })
    } else {
      // JWT
      const result = await client.verifyJwt(token, appId || undefined)

      if (!result.data) {
        throw err(result.error?.message || '认证失败', 401)
      }

      if (result.data.status === 'disabled') {
        throw err('账号已被禁用', 401)
      }
      if (result.data.status === 'deleted') {
        throw err('账号已被删除', 401)
      }

      return next({ userInfo: result.data })
    }
  })
}

// ============ App 验证中间件 ============

/** App 验证上下文 */
export interface ValidateAppContext {
  app: AppInfo
}

/**
 * App 验证中间件
 * 
 * 验证请求头中的 app-id 是否有效
 * 
 * @param config 可选配置，不传则从环境变量读取
 * @param options 验证选项
 * 
 * @example
 * ```ts
 * // 方式1：无参数，自动读取环境变量
 * const appValidator = validateApp()
 * 
 * // 方式2：手动配置
 * const appValidator = validateApp({ baseUrl: 'http://localhost:9003' })
 * 
 * // 可选 app-id
 * const appValidatorOptional = validateApp(undefined, { required: false })
 * 
 * // 只检查 header 存在，不网络验证（轻量级）
 * const appIdChecker = validateApp(undefined, { verify: false })
 * ```
 */
export function validateApp(config?: AuthMiddlewareOptions, options?: ValidateAppOptions) {
  const client = getClient(config)
  const required = options?.required ?? true
  const verify = options?.verify ?? true

  return defineMiddleware<ValidateAppContext>(async (req, next) => {
    const appId = req.headers.get('app-id')

    if (!appId) {
      if (required) {
        return Response.json({ code: 400, message: '缺少必需的请求头: app-id' }, { status: 400 })
      }
      // required: false 时不注入 app
      return next()
    }

    // 不验证，创建最小化 app 对象
    if (!verify) {
      return next({
        app: {
          id: appId,
          name: '',
          status: 'active'
        }
      })
    }

    // 调用 auth-server 验证
    const result = await client.verifyApp(appId)

    if (!result.data?.valid || !result.data.app) {
      if (required) {
        return Response.json({ code: 400, message: result.data?.message || '无效的 app-id' }, { status: 400 })
      }
      // required: false 时也不注入无效的 app
      return next()
    }

    // 统一返回完整的 app 对象
    return next({ app: result.data.app })
  })
}

// ============ Guards（守卫层）============
// 
// 守卫是轻量级检查，不发网络请求，只检查上下文条件
// 命名规范：require* = 要求某个条件满足

/** 从请求中获取上下文 */
function getLocals<T>(req: Request): T | undefined {
  const target = req as unknown as { __locals?: T }
  return target.__locals
}

/**
 * 要求用户已认证
 * 
 * 检查上下文中 userInfo 是否存在，没有则返回 401
 * 
 * @example
 * ```ts
 * middleware: [auth, requireUser]
 * ```
 */
export const requireUser = defineMiddleware(async (req, next) => {
  const ctx = getLocals<{ userInfo?: UserInfo }>(req)
  if (!ctx?.userInfo) {
    return Response.json(
      { code: 401, message: '未登录或用户信息缺失' },
      { status: 401 }
    )
  }
  return next()
})

/**
 * 要求 App 已验证
 * 
 * 检查上下文中 app 是否存在，没有则返回 400
 * 需配合 validateApp 中间件使用
 * 
 * @example
 * ```ts
 * middleware: [appValidator, requireApp]
 * ```
 */
export const requireApp = defineMiddleware(async (req, next) => {
  const ctx = getLocals<ValidateAppContext>(req)
  if (!ctx?.app) {
    return Response.json(
      { code: 400, message: '缺少有效的 app-id' },
      { status: 400 }
    )
  }
  return next()
})

/**
 * 要求 API Key 已认证
 * 
 * 检查上下文中 apiKey 是否存在，没有则返回 401
 * 
 * @example
 * ```ts
 * middleware: [apiKeyAuth, requireApiKey]
 * ```
 */
export const requireApiKey = defineMiddleware(async (req, next) => {
  const ctx = getLocals<ApiKeyContext>(req)
  if (!ctx?.apiKey) {
    return Response.json(
      { code: 401, message: '无效的 API Key' },
      { status: 401 }
    )
  }
  return next()
})

// ============ requireUserAndApp（与 auth-server 对齐）============

/**
 * 要求用户已认证且有 app
 * 
 * 同时检查上下文中 userInfo 和 app 是否存在
 * 需配合 [auth, appValidator] 中间件使用
 * 
 * @example
 * ```ts
 * middleware: [auth, appValidator, requireUserAndApp]
 * ```
 */
export const requireUserAndApp = defineMiddleware(async (req, next) => {
  const ctx = getLocals<{ userInfo?: UserInfo; app?: AppInfo }>(req)

  if (!ctx?.userInfo) {
    return Response.json(
      { code: 401, message: '未登录或用户信息缺失' },
      { status: 401 }
    )
  }

  if (!ctx?.app) {
    return Response.json(
      { code: 400, message: '缺少有效的 app-id' },
      { status: 400 }
    )
  }

  return next()
})


// ============ Webhook 扩展类型 ============

/**
 * Webhook 配置选项（详细配置）
 */
export interface WebhookConfigOptions {
  /** 自定义事件 key（默认从路径自动生成） */
  eventKey?: string
  /** 要包含在 payload 中的字段（白名单） */
  include?: string[]
  /** 要从 payload 中排除的字段（黑名单） */
  exclude?: string[]
}

/**
 * 路由扩展类型
 *
 * 内置 webhook 支持，同时允许自定义扩展字段
 *
 * @example
 * ```typescript
 * // webhook 有精确类型提示
 * defineAuthRouteWithApp({
 *   method: 'POST',
 *   path: '/create',
 *   webhook: true,
 *   handler: ...
 * })
 *
 * // 自定义扩展也支持（通过索引签名）
 * defineAuthRouteWithApp({
 *   method: 'POST',
 *   path: '/admin',
 *   webhook: { exclude: ['password'] },
 *   permission: 'admin',  // 自定义扩展字段
 *   rateLimit: 100,       // 其他扩展
 *   handler: ...
 * })
 * ```
 */
export interface RouteExtensions {
  /** Webhook 配置：启用后该路由的响应会触发 webhook 事件 */
  readonly webhook?: boolean | WebhookConfigOptions
  /** 允许其他自定义扩展字段 */
  readonly [key: string]: unknown
}

// ============ 带上下文的路由定义器 ============

/**
 * 带 UserInfo 上下文的路由定义器
 *
 * 内置 webhook 支持，用于需要认证但不需要 app-id 的路由
 *
 * @example
 * ```typescript
 * import { defineAuthRoute, requireUser } from '@vafast/auth-middleware'
 *
 * defineAuthRoute({
 *   method: 'GET',
 *   path: '/profile',
 *   middleware: [requireUser],
 *   handler: ({ userInfo }) => ({ id: userInfo.id })
 * })
 *
 * // 带 webhook
 * defineAuthRoute({
 *   method: 'POST',
 *   path: '/update',
 *   webhook: true,
 *   handler: ({ userInfo }) => ({ ... })
 * })
 * ```
 */
export const defineAuthRoute = withContext<{ userInfo: UserInfo }, RouteExtensions>()

/**
 * 带可选 UserInfo 上下文的路由定义器
 *
 * 内置 webhook 支持
 */
export const defineOptionalAuthRoute = withContext<{ userInfo?: UserInfo }, RouteExtensions>()

/**
 * 带 ApiKey 上下文的路由定义器
 *
 * 内置 webhook 支持
 */
export const defineApiKeyRoute = withContext<ApiKeyContext, RouteExtensions>()

/**
 * 带 UserInfo 和 app 上下文的路由定义器（最常用）
 *
 * 内置 webhook 支持，用于需要认证且需要 app 验证的路由
 *
 * @example
 * ```typescript
 * import { auth, appValidator, defineAuthRouteWithApp } from '@vafast/auth-middleware'
 *
 * // 普通路由
 * defineAuthRouteWithApp({
 *   method: 'GET',
 *   path: '/info',
 *   middleware: [auth, appValidator],
 *   handler: ({ userInfo, app }) => ({ userId: userInfo.id, appId: app.id })
 * })
 *
 * // 带 webhook
 * defineAuthRouteWithApp({
 *   method: 'POST',
 *   path: '/create',
 *   webhook: true,
 *   middleware: [auth, appValidator],
 *   handler: ({ userInfo, app }) => ({ ... })
 * })
 *
 * // webhook 详细配置
 * defineAuthRouteWithApp({
 *   method: 'POST',
 *   path: '/update',
 *   webhook: { exclude: ['password', 'secret'] },
 *   handler: ({ userInfo, app }) => ({ ... })
 * })
 * ```
 */
export const defineAuthRouteWithApp = withContext<{ userInfo: UserInfo; app: AppInfo }, RouteExtensions>()

/**
 * 只带 app 上下文的路由定义器
 *
 * 内置 webhook 支持
 */
export const defineRouteWithApp = withContext<{ app: AppInfo }, RouteExtensions>()

/**
 * 可选认证 + app 上下文的路由定义器
 *
 * 内置 webhook 支持
 *
 * @example
 * ```typescript
 * import { auth, appValidator, defineOptionalAuthRouteWithApp } from '@vafast/auth-middleware'
 *
 * defineOptionalAuthRouteWithApp({
 *   method: 'GET',
 *   path: '/public',
 *   middleware: [appValidator],
 *   handler: ({ userInfo, app }) => {
 *     // 已登录用户有 userInfo
 *     return { appId: app.id }
 *   }
 * })
 * ```
 */
export const defineOptionalAuthRouteWithApp = withContext<{ userInfo?: UserInfo; app: AppInfo }, RouteExtensions>()

/**
 * 带完整认证上下文的路由定义器
 *
 * 内置 webhook 支持，包含 userInfo、apiKey（可选）和 app
 */
export const defineFullAuthRoute = withContext<
  { userInfo: UserInfo; apiKey?: ApiKeyInfo; app: AppInfo },
  RouteExtensions
>()

// ============ 语义化函数导出 ============
// 更清晰的命名，推荐使用

/**
 * JWT + API Key 混合认证（推荐）
 * 
 * 语义化别名，内部调用 authenticate
 */
export function authJwtAndApiKey(options?: AuthMiddlewareOptions) {
  return authenticate(options)
}

/**
 * 仅 JWT 认证
 * 
 * 语义化别名，内部调用 authenticateJwt
 */
export function authJwt(options?: AuthMiddlewareOptions) {
  return authenticateJwt(options)
}

/**
 * 仅 API Key 认证
 * 
 * 语义化别名，内部调用 authenticateApiKey
 */
export function authApiKey(options?: AuthMiddlewareOptions) {
  return authenticateApiKey(options)
}

/**
 * 验证 App ID
 * 
 * 语义化别名，内部调用 validateApp
 */
export function validateAppId(config?: AuthMiddlewareOptions, options?: ValidateAppOptions) {
  return validateApp(config, options)
}

// ============ 预配置中间件（懒加载单例） ============
// 最简洁用法：middleware: [auth, appValidator]

let _sharedClient: AuthClient | null = null

/** 获取共享客户端（懒加载） */
function getSharedClient(): AuthClient {
  if (!_sharedClient) {
    _sharedClient = createAuthClient()
  }
  return _sharedClient
}

/** 预配置的混合认证中间件（懒加载） */
export const auth = defineMiddleware<ApiKeyContext>(async (req, next) => {
  const client = getSharedClient()
  const authorization = req.headers.get('authorization')
  const appId = req.headers.get('app-id')

  if (!authorization || !authorization.startsWith('Bearer ')) {
    throw err('未提供认证信息', 401)
  }

  const token = authorization.slice(7)
  if (!token) {
    throw err('未提供认证信息', 401)
  }

  // API Key 格式: ak_xxx:sk_xxx
  if (token.includes(':')) {
    const [keyId, keySecret] = token.split(':')
    if (!keyId || !keySecret) {
      throw err('无效的 API Key 格式', 401)
    }
    const result = await client.verifyApiKey(keyId, keySecret)
    if (!result.data) {
      throw err(result.error?.message || 'API Key 验证失败', 401)
    }
    return next({ userInfo: result.data.userInfo, apiKey: result.data.apiKey })
  }

  // JWT
  const result = await client.verifyJwt(token, appId || undefined)
  if (!result.data) {
    throw err(result.error?.message || '认证失败', 401)
  }
  if (result.data.status === 'disabled') {
    throw err('账号已被禁用', 401)
  }
  if (result.data.status === 'deleted') {
    throw err('账号已被删除', 401)
  }
  return next({ userInfo: result.data })
})

/** 预配置的 JWT 认证中间件（懒加载） */
export const jwtAuth = defineMiddleware<{ userInfo: UserInfo }>(async (req, next) => {
  const client = getSharedClient()
  const authorization = req.headers.get('authorization')
  const appId = req.headers.get('app-id')

  if (!authorization || !authorization.startsWith('Bearer ')) {
    throw err('未提供认证信息', 401)
  }
  const jwtToken = authorization.slice(7)
  if (!jwtToken) {
    throw err('未提供认证信息', 401)
  }
  if (jwtToken.includes(':')) {
    throw err('无效的 JWT Token', 401)
  }
  const result = await client.verifyJwt(jwtToken, appId || undefined)
  if (!result.data) {
    throw err(result.error?.message || '认证失败', 401)
  }
  if (result.data.status === 'disabled') {
    throw err('账号已被禁用', 401)
  }
  if (result.data.status === 'deleted') {
    throw err('账号已被删除', 401)
  }
  return next({ userInfo: result.data })
})

/** 预配置的 API Key 认证中间件（懒加载） */
export const apiKeyAuth = defineMiddleware<ApiKeyContext>(async (req, next) => {
  const client = getSharedClient()
  const authorization = req.headers.get('authorization')

  if (!authorization || !authorization.startsWith('Bearer ')) {
    throw err('未提供认证信息', 401)
  }
  const token = authorization.slice(7)
  if (!token || !token.includes(':')) {
    throw err('无效的 API Key 格式', 401)
  }
  const [keyId, keySecret] = token.split(':')
  if (!keyId || !keySecret) {
    throw err('无效的 API Key 格式', 401)
  }
  const result = await client.verifyApiKey(keyId, keySecret)
  if (!result.data) {
    throw err(result.error?.message || 'API Key 验证失败', 401)
  }
  return next({ userInfo: result.data.userInfo, apiKey: result.data.apiKey })
})

/** 预配置的 App 验证中间件（懒加载） */
export const appValidator = defineMiddleware<ValidateAppContext>(async (req, next) => {
  const client = getSharedClient()
  const appId = req.headers.get('app-id')

  if (!appId) {
    return Response.json({ code: 400, message: '缺少必需的请求头: app-id' }, { status: 400 })
  }

  const result = await client.verifyApp(appId)
  if (!result.data?.valid || !result.data.app) {
    return Response.json({ code: 400, message: result.data?.message || '无效的 app-id' }, { status: 400 })
  }

  // 统一返回完整的 app 对象
  return next({ app: result.data.app })
})

