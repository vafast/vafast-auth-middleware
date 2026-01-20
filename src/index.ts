/**
 * @vafast/auth-middleware
 * 
 * Vafast 认证中间件 - 完整的 JWT/API Key 验证解决方案
 * 
 * 特点：
 * - 开箱即用：内置 auth-server 客户端，无需额外依赖
 * - 软认证模式：验证失败也继续执行（让后续 guard 处理权限）
 * - 支持 JWT 和 API Key 两种认证方式
 * - 可选依赖注入：高级用户可自定义验证函数
 */

import { defineMiddleware, withContext } from 'vafast'

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
  /** auth-server 基础 URL，如 http://localhost:9003 */
  baseUrl: string
  /** 服务间通信使用的 API Key ID（可选） */
  apiKeyId?: string
  /** 服务间通信使用的 API Key Secret（可选） */
  apiKeySecret?: string
  /** 请求超时时间（毫秒），默认 5000 */
  timeout?: number
}

// ============ 内置 Auth Client ============

/**
 * 创建 Auth 客户端
 * 
 * 内置的 auth-server 客户端，使用原生 fetch 实现
 */
export function createAuthClient(config: AuthClientConfig) {
  const { baseUrl, apiKeyId, apiKeySecret, timeout = 5000 } = config

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
     */
    async verifyJwt(token: string, appId?: string): Promise<ApiResult<UserInfo>> {
      return callAuthApi<UserInfo>('/authRestfulApi/verify/jwt', { token, appId })
    },

    /**
     * 验证 API Key
     */
    async verifyApiKey(
      apiKeyId: string,
      secretKey: string
    ): Promise<ApiResult<{ userInfo: UserInfo; apiKey: ApiKeyInfo }>> {
      return callAuthApi<{ userInfo: UserInfo; apiKey: ApiKeyInfo }>(
        '/authRestfulApi/verify/api-key',
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

/** 认证中间件选项：直接传配置或已创建的客户端 */
export type AuthMiddlewareOptions = AuthClientConfig | AuthClient

/** App 验证中间件选项 */
export interface ValidateAppOptions {
  /** 是否必须提供 app-id，默认 true */
  required?: boolean
  /** 是否调用 auth-server 验证 app-id 有效性，默认 true */
  verify?: boolean
}

// ============ 辅助函数 ============

/** 判断是否为 AuthClient 实例 */
function isAuthClient(obj: AuthMiddlewareOptions): obj is AuthClient {
  return 'verifyJwt' in obj && typeof obj.verifyJwt === 'function'
}

/** 获取或创建 AuthClient 实例 */
function getClient(options: AuthMiddlewareOptions): AuthClient {
  if (isAuthClient(options)) {
    return options
  }
  return createAuthClient(options)
}

// ============ JWT 认证中间件 ============

/**
 * JWT 认证中间件
 * 
 * 从请求头提取 JWT，调用 auth-server 验证，将用户信息注入上下文
 * 
 * @example
 * ```ts
 * import { authenticateJwt } from '@vafast/auth-middleware'
 * 
 * const jwtAuth = authenticateJwt({
 *   baseUrl: 'http://localhost:9003',
 *   apiKeyId: 'ak_xxx',
 *   apiKeySecret: 'sk_xxx',
 * })
 * ```
 */
export function authenticateJwt(options: AuthMiddlewareOptions) {
  const client = getClient(options)

  return defineMiddleware<{ userInfo?: UserInfo }>(async (req, next) => {
    const authorization = req.headers.get('authorization')
    const appId = req.headers.get('app-id')

    // 无 authorization，继续执行（软认证）
    if (!authorization) {
      return next()
    }

    // 强制要求 Bearer 前缀，否则跳过
    if (!authorization.startsWith('Bearer ')) {
      return next()
    }

    const jwtToken = authorization.slice(7)
    if (!jwtToken) {
      return next()
    }

    // 如果是 API Key 格式（包含冒号），跳过 JWT 验证
    if (jwtToken.includes(':')) {
      return next()
    }

    // 调用 auth-server API 验证 JWT
    const result = await client.verifyJwt(jwtToken, appId || undefined)

    if (result.data) {
      // 检查用户状态
      if (result.data.status === 'disabled' || result.data.status === 'deleted') {
        return next()
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
    }

    return next()
  })
}

// ============ API Key 认证中间件 ============

/** API Key 认证上下文 */
export interface ApiKeyContext {
  userInfo?: UserInfo
  apiKey?: ApiKeyInfo
}

/**
 * API Key 认证中间件
 * 
 * 从请求头提取 API Key，调用 auth-server 验证，将用户信息和 API Key 信息注入上下文
 * 
 * @example
 * ```ts
 * const apiKeyAuth = authenticateApiKey({ baseUrl: 'http://localhost:9003' })
 * ```
 */
export function authenticateApiKey(options: AuthMiddlewareOptions) {
  const client = getClient(options)

  return defineMiddleware<ApiKeyContext>(async (req, next) => {
    const authorization = req.headers.get('authorization')

    // 无 authorization，继续执行（软认证）
    if (!authorization) {
      return next()
    }

    // 强制要求 Bearer 前缀
    if (!authorization.startsWith('Bearer ')) {
      return next()
    }

    const token = authorization.slice(7)
    if (!token) {
      return next()
    }

    // API Key 格式：apiKeyId:secretKey
    if (!token.includes(':')) {
      return next()
    }

    const [apiKeyId, secretKey] = token.split(':')
    if (!apiKeyId || !secretKey) {
      return next()
    }

    // 调用 auth-server API 验证 API Key
    const result = await client.verifyApiKey(apiKeyId, secretKey)

    if (result.data) {
      return next({
        userInfo: result.data.userInfo,
        apiKey: result.data.apiKey,
      })
    }

    return next()
  })
}

// ============ 混合认证中间件 ============

/**
 * 混合认证中间件
 * 
 * 同时支持 JWT 和 API Key 认证，自动识别认证方式
 * 
 * @example
 * ```ts
 * const auth = authenticate({ baseUrl: 'http://localhost:9003', apiKeyId: 'ak_xxx', apiKeySecret: 'sk_xxx' })
 * ```
 */
export function authenticate(options: AuthMiddlewareOptions) {
  const client = getClient(options)

  return defineMiddleware<ApiKeyContext>(async (req, next) => {
    const authorization = req.headers.get('authorization')
    const appId = req.headers.get('app-id')

    if (!authorization || !authorization.startsWith('Bearer ')) {
      return next()
    }

    const token = authorization.slice(7)
    if (!token) {
      return next()
    }

    if (token.includes(':')) {
      // API Key
      const [apiKeyId, secretKey] = token.split(':')
      if (apiKeyId && secretKey) {
        const result = await client.verifyApiKey(apiKeyId, secretKey)
        if (result.data) {
          return next({ userInfo: result.data.userInfo, apiKey: result.data.apiKey })
        }
      }
    } else {
      // JWT
      const result = await client.verifyJwt(token, appId || undefined)
      if (result.data && result.data.status !== 'disabled' && result.data.status !== 'deleted') {
        return next({ userInfo: result.data })
      }
    }

    return next()
  })
}

// ============ App 验证中间件 ============

/** App 验证上下文 */
export interface ValidateAppContext {
  app?: AppInfo
  appId?: string
}

/**
 * App 验证中间件
 * 
 * 验证请求头中的 app-id 是否有效
 * 
 * @example
 * ```ts
 * // 完整验证（调用 auth-server）
 * const appValidator = validateApp({ baseUrl: 'http://localhost:9003' })
 * 
 * // 可选 app-id
 * const appValidatorOptional = validateApp({ baseUrl: '...' }, { required: false })
 * 
 * // 只检查 header 存在，不网络验证（轻量级）
 * const appIdChecker = validateApp({ baseUrl: '...' }, { verify: false })
 * ```
 */
export function validateApp(config: AuthMiddlewareOptions, options?: ValidateAppOptions) {
  const client = getClient(config)
  const required = options?.required ?? true
  const verify = options?.verify ?? true

  return defineMiddleware<ValidateAppContext>(async (req, next) => {
    const appId = req.headers.get('app-id')

    if (!appId) {
      if (required) {
        return Response.json({ code: 400, message: '缺少必需的请求头: app-id' }, { status: 400 })
      }
      return next()
    }

    // 不验证，只返回 appId
    if (!verify) {
      return next({ appId })
    }

    // 调用 auth-server 验证
    const result = await client.verifyApp(appId)

    if (result.data?.valid && result.data.app) {
      return next({ app: result.data.app, appId })
    }

    if (required) {
      return Response.json({ code: 400, message: result.data?.message || '无效的 app-id' }, { status: 400 })
    }

    return next({ appId })
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
 * 检查上下文中 app 或 appId 是否存在，没有则返回 400
 * 需配合 validateApp 中间件使用
 * 
 * @example
 * ```ts
 * middleware: [appValidator, requireApp]
 * ```
 */
export const requireApp = defineMiddleware(async (req, next) => {
  const ctx = getLocals<ValidateAppContext>(req)
  if (!ctx?.app && !ctx?.appId) {
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

// ============ 别名（向后兼容）============

/** @deprecated 请使用 requireUser */
export const requireAuth = requireUser


// ============ 带上下文的路由定义器 ============

/**
 * 带 UserInfo 上下文的路由定义器
 * 
 * 用于需要认证但不需要 app-id 的路由
 * 需配合认证中间件使用
 * 
 * @example
 * ```typescript
 * import { defineAuthRoute, requireAuth } from '@vafast/auth-middleware'
 * 
 * defineAuthRoute({
 *   method: 'GET',
 *   path: '/profile',
 *   middleware: [requireAuth],
 *   handler: ({ userInfo }) => {
 *     // userInfo 自动有类型
 *     return { id: userInfo.id }
 *   }
 * })
 * ```
 */
export const defineAuthRoute = withContext<{ userInfo: UserInfo }>()

/**
 * 带可选 UserInfo 上下文的路由定义器
 * 
 * 用于可能有/没有认证的路由
 * 
 * @example
 * ```typescript
 * defineOptionalAuthRoute({
 *   method: 'GET',
 *   path: '/public',
 *   handler: ({ userInfo }) => {
 *     // userInfo 可能为 undefined
 *     return { loggedIn: !!userInfo }
 *   }
 * })
 * ```
 */
export const defineOptionalAuthRoute = withContext<{ userInfo?: UserInfo }>()

/**
 * 带 ApiKey 上下文的路由定义器
 * 
 * 用于需要 API Key 认证的路由
 * 需配合 [authenticateApiKey, requireApiKey] 中间件使用
 */
export const defineApiKeyRoute = withContext<ApiKeyContext>()

/**
 * 带 UserInfo 和 appId 上下文的路由定义器
 * 
 * 用于需要认证且需要 app-id 的路由（最常用）
 * 需配合 [authenticate, requireAuth, appValidator] 中间件使用
 * 
 * @example
 * ```typescript
 * import { defineAuthRouteWithApp, createAuth } from '@vafast/auth-middleware'
 * const { auth, appValidator, requireAuth } = createAuth()
 * 
 * defineAuthRouteWithApp({
 *   method: 'POST',
 *   path: '/update',
 *   middleware: [auth, appValidator, requireAuth],
 *   handler: ({ userInfo, app }) => {
 *     // userInfo 和 app 都有类型
 *     return { userId: userInfo.id, appId: app.id }
 *   }
 * })
 * ```
 */
export const defineAuthRouteWithApp = withContext<{ userInfo: UserInfo; app: AppInfo }>()

/**
 * 只带 app 上下文的路由定义器
 * 
 * 用于需要 app 验证但不需要用户认证的路由
 * 需配合 appValidator 中间件使用
 */
export const defineRouteWithApp = withContext<{ app: AppInfo }>()

/**
 * 带完整认证上下文的路由定义器
 * 
 * 包含 userInfo、apiKey（可选）和 app
 * 用于混合认证场景
 */
export const defineFullAuthRoute = withContext<{
  userInfo: UserInfo
  apiKey?: ApiKeyInfo
  app: AppInfo
}>()

