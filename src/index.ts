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

/**
 * 服务准入状态，由 auth-server 在验证响应中按 app 下发
 *
 * 邀请制是接入应用的通用机制：每个 app 通过 `inviteAccess.enabled` 独立开关。
 * 未开启时 granted 恒为 true，行为与未接入邀请制时完全一致。
 */
export interface ServiceAccessInfo {
  /** 该 app 是否开启邀请制 */
  inviteOnly: boolean
  /** 最终准入结论：应用未开启邀请制时恒为 true */
  granted: boolean
  status: 'granted' | 'waitlisted'
}

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
  /** 组织成员所属组织。组织成员身份直接归属 organization。 */
  organizationId?: string
  /** organization_member 表示组织成员，customer_user 表示客户应用终端用户。 */
  accountType?: string
  /** 组织成员跨 app 访问时为 true，用于区分后台账号和目标 app 终端用户身份 */
  isOrgMemberAccess?: boolean
  /** 本次请求 app-id 指向的目标 app，跨 app 访问时与用户原始 appId 不同 */
  targetAppId?: string
  /** 本次访问模式：direct 为当前 app 用户直接访问，org_member_delegate 为组织成员代理访问。 */
  accessMode?: 'direct' | 'org_member_delegate'
  /** 服务准入状态。由 auth-server 按当前 app 下发；默认认证会据此拦截候补账号。 */
  serviceAccess?: ServiceAccessInfo
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
  /** auth-server 维护的 app 结构化扩展，如 organizationId */
  extensions?: Record<string, unknown>
  [key: string]: unknown
}

/** JWT 验证结果，可携带已验证的 app 摘要 */
export interface VerifiedUserInfo extends UserInfo {
  app?: AppInfo
}

/** API 响应结果 */
export interface ApiResult<T> {
  data?: T
  error?: { code: number; message: string }
}

const AUTH_API_TIMEOUT_CODE = 504
const AUTH_API_UNAVAILABLE_CODE = 503

function isAbortError(error: unknown) {
  return error instanceof Error && error.name === 'AbortError'
}

function normalizeAuthApiError(error: unknown): { code: number; message: string } {
  if (isAbortError(error)) {
    return {
      code: AUTH_API_TIMEOUT_CODE,
      message: '认证服务响应超时，请稍后重试',
    }
  }
  return {
    code: AUTH_API_UNAVAILABLE_CODE,
    message: '认证服务暂时不可用，请稍后重试',
  }
}

function normalizeAuthFailureStatus(code: number | undefined, fallbackStatus: number) {
  if (code && code >= 400 && code <= 599) {
    return code
  }
  return fallbackStatus
}

function throwAuthFailure(errorInfo: ApiResult<unknown>['error'], fallbackMessage: string, fallbackStatus: number): never {
  const status = normalizeAuthFailureStatus(errorInfo?.code, fallbackStatus)
  throw err(errorInfo?.message || fallbackMessage, status)
}

/** 从请求中获取上下文 */
function getLocals<T>(req: Request): T | undefined {
  const target = req as unknown as { __locals?: T }
  return target.__locals
}

// ============ 服务准入闸门（接入应用通用邀请制） ============

/** 账号未开通服务时返回的业务码，前端据此引导至候补页 */
export const SERVICE_ACCESS_WAITLISTED_CODE = 4030001

/** 账号未开通服务时的提示文案 */
export const SERVICE_ACCESS_WAITLISTED_MESSAGE
  = '当前处于邀请制内测，账号尚未开通服务，请填写邀请码或等待开通通知'

type AuthMiddlewareFn<T extends object = object> = (
  req: Request,
  next: (ctx?: T) => Promise<Response>,
) => Promise<Response>

/**
 * 未开通时返回 403，放行时返回 null
 *
 * 不走 throwAuthFailure：业务码 4030001 超出 400-599 会被归一成 401。
 * auth-server 未下发 serviceAccess 时放行，兼容旧版本。
 * 应用未开启 inviteAccess 时 granted 恒为 true，不会进入此分支。
 */
function denyIfWaitlisted(userInfo: UserInfo | undefined, enforce: boolean): Response | null {
  if (!enforce || userInfo?.serviceAccess?.granted !== false) {
    return null
  }
  return Response.json(
    { code: SERVICE_ACCESS_WAITLISTED_CODE, message: SERVICE_ACCESS_WAITLISTED_MESSAGE },
    { status: 403 },
  )
}

/**
 * 把服务准入叠在「已认证」中间件之后
 *
 * 认证只回答「你是谁」；本函数只回答「这个 app 能不能用」。
 * 默认 enforce=true。候补用户也要访问的接口传入 false，或直接使用 *AllowWaitlisted 导出。
 */
export function withServiceAccess<T extends { userInfo?: UserInfo }>(
  middleware: AuthMiddlewareFn<T>,
  enforce = true,
) {
  return defineMiddleware<T>(async (req, next) => {
    return middleware(req, async (ctx?: T) => {
      const userInfo = ctx?.userInfo ?? getLocals<{ userInfo?: UserInfo }>(req)?.userInfo
      const denied = denyIfWaitlisted(userInfo, enforce)
      if (denied) {
        return denied
      }
      if (ctx) {
        return next(ctx)
      }
      return next()
    })
  })
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
      const normalized = normalizeAuthApiError(error)
      return {
        error: normalized,
      }
    }
  }

  return {
    /**
     * 验证 JWT Token
     * 注意：使用独立的 /verifyJwt 路由，不需要 app-id header
     */
    async verifyJwt(token: string, appId?: string): Promise<ApiResult<VerifiedUserInfo>> {
      return callAuthApi<VerifiedUserInfo>('/verifyJwt', { token, appId })
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
        '/verifyApiKey',
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
        '/apps/verify',
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
        '/users/batch',
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
        '/users/find',
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
        '/users/statistics',
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

function ensureActiveUser(user: UserInfo) {
  if (user.status === 'disabled') {
    throw err('账号已被禁用', 401)
  }
  if (user.status === 'deleted') {
    throw err('账号已被删除', 401)
  }
}

/** 读取 Bearer token，缺失或格式不对时 401 */
function readBearerToken(req: Request): string {
  const authorization = req.headers.get('authorization')
  if (!authorization || !authorization.startsWith('Bearer ')) {
    throw err('未提供认证信息', 401)
  }
  const token = authorization.slice(7)
  if (!token) {
    throw err('未提供认证信息', 401)
  }
  return token
}

function isApiKeyToken(token: string) {
  return token.includes(':')
}

function splitApiKey(token: string): { apiKeyId: string; secretKey: string } {
  const [apiKeyId, secretKey] = token.split(':')
  if (!apiKeyId || !secretKey) {
    throw err('无效的 API Key 格式', 401)
  }
  return { apiKeyId, secretKey }
}

/**
 * 向 auth-server 验 JWT，原样带回 userInfo（含 serviceAccess 等扩展字段）
 *
 * appId 仅在响应缺省时回退到请求头，不再手工拼一份字段子集。
 */
async function verifyJwtIdentity(
  client: AuthClient,
  token: string,
  appId?: string | null,
): Promise<VerifiedUserInfo> {
  const result = await client.verifyJwt(token, appId || undefined)
  if (!result.data) {
    throwAuthFailure(result.error, '认证失败', 401)
  }
  ensureActiveUser(result.data)
  return {
    ...result.data,
    appId: result.data.appId || appId || '',
  }
}

async function verifyApiKeyIdentity(
  client: AuthClient,
  token: string,
): Promise<{ userInfo: UserInfo; apiKey: ApiKeyInfo }> {
  const { apiKeyId, secretKey } = splitApiKey(token)
  const result = await client.verifyApiKey(apiKeyId, secretKey)
  if (!result.data) {
    throwAuthFailure(result.error, 'API Key 验证失败', 401)
  }
  return {
    userInfo: result.data.userInfo,
    apiKey: result.data.apiKey,
  }
}

function getValidatedAppFromLocals(req: Request, appId: string): AppInfo | undefined {
  const ctx = getLocals<{ app?: AppInfo; userInfo?: VerifiedUserInfo }>(req)
  if (ctx?.app?.id === appId) {
    return ctx.app
  }
  if (ctx?.userInfo?.app?.id === appId) {
    return ctx.userInfo.app
  }
  return undefined
}

// ============ 身份认证中间件（不含服务准入） ============

/** API Key 认证上下文 */
export interface ApiKeyContext {
  userInfo?: UserInfo
  apiKey?: ApiKeyInfo
}

/** App 验证上下文 */
export interface ValidateAppContext {
  app: AppInfo
}

/** 认证并验证 App 的上下文 */
export interface AuthWithAppContext {
  userInfo: UserInfo
  apiKey?: ApiKeyInfo
  app: AppInfo
}

function jwtIdentity(resolveClient: () => AuthClient) {
  return defineMiddleware<{ userInfo: UserInfo }>(async (req, next) => {
    const token = readBearerToken(req)
    if (isApiKeyToken(token)) {
      throw err('无效的 JWT Token', 401)
    }
    const userInfo = await verifyJwtIdentity(resolveClient(), token, req.headers.get('app-id'))
    return next({ userInfo })
  })
}

function apiKeyIdentity(resolveClient: () => AuthClient) {
  return defineMiddleware<ApiKeyContext>(async (req, next) => {
    const token = readBearerToken(req)
    if (!isApiKeyToken(token)) {
      throw err('无效的 API Key 格式', 401)
    }
    return next(await verifyApiKeyIdentity(resolveClient(), token))
  })
}

function mixedIdentity(resolveClient: () => AuthClient) {
  return defineMiddleware<ApiKeyContext>(async (req, next) => {
    const token = readBearerToken(req)
    if (isApiKeyToken(token)) {
      return next(await verifyApiKeyIdentity(resolveClient(), token))
    }
    const userInfo = await verifyJwtIdentity(resolveClient(), token, req.headers.get('app-id'))
    return next({ userInfo })
  })
}

function authWithAppIdentity(resolveClient: () => AuthClient) {
  return defineMiddleware<AuthWithAppContext>(async (req, next) => {
    const appId = req.headers.get('app-id')
    if (!appId) {
      return Response.json({ code: 400, message: '缺少必需的请求头: app-id' }, { status: 400 })
    }

    const token = readBearerToken(req)
    if (isApiKeyToken(token)) {
      const creds = await verifyApiKeyIdentity(resolveClient(), token)
      const appResult = await resolveClient().verifyApp(appId)
      if (!appResult.data?.valid || !appResult.data.app) {
        const status = normalizeAuthFailureStatus(appResult.error?.code, 400)
        return Response.json({
          code: status,
          message: appResult.error?.message || appResult.data?.message || '无效的 app-id',
        }, { status })
      }
      return next({
        userInfo: creds.userInfo,
        apiKey: creds.apiKey,
        app: appResult.data.app,
      })
    }

    const userInfo = await verifyJwtIdentity(resolveClient(), token, appId)
    if (!userInfo.app) {
      throw err('无效的 app-id', 400)
    }
    return next({ userInfo, app: userInfo.app })
  })
}

function resolveFactoryClient(options?: AuthMiddlewareOptions) {
  const client = getClient(options)
  return () => client
}

/**
 * JWT 认证中间件（硬认证 + 默认服务准入）
 *
 * 从请求头提取 JWT，调用 auth-server 验证，将用户信息注入上下文
 * 验证失败直接返回 401；候补账号默认 403。
 *
 * @param options 可选配置，不传则从环境变量读取
 *
 * @example
 * ```ts
 * const jwtAuth = authenticateJwt()
 * const jwtAuth = authenticateJwt({ baseUrl: 'http://localhost:9003' })
 * ```
 */
export function authenticateJwt(options?: AuthMiddlewareOptions) {
  return withServiceAccess(jwtIdentity(resolveFactoryClient(options)))
}

/** JWT 认证，跳过服务准入。仅用于候补用户也必须访问的接口。 */
export function authenticateJwtAllowWaitlisted(options?: AuthMiddlewareOptions) {
  return jwtIdentity(resolveFactoryClient(options))
}

/**
 * API Key 认证中间件（硬认证 + 默认服务准入）
 *
 * 从请求头提取 API Key，调用 auth-server 验证，将用户信息和 API Key 信息注入上下文
 * 验证失败直接返回 401
 */
export function authenticateApiKey(options?: AuthMiddlewareOptions) {
  return withServiceAccess(apiKeyIdentity(resolveFactoryClient(options)))
}

/** API Key 认证，跳过服务准入。 */
export function authenticateApiKeyAllowWaitlisted(options?: AuthMiddlewareOptions) {
  return apiKeyIdentity(resolveFactoryClient(options))
}

/**
 * 混合认证中间件（硬认证 + 默认服务准入）
 *
 * 同时支持 JWT 和 API Key 认证，自动识别认证方式
 * 验证失败直接返回 401
 */
export function authenticate(options?: AuthMiddlewareOptions) {
  return withServiceAccess(mixedIdentity(resolveFactoryClient(options)))
}

/** 混合认证，跳过服务准入。 */
export function authenticateAllowWaitlisted(options?: AuthMiddlewareOptions) {
  return mixedIdentity(resolveFactoryClient(options))
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
 * const appValidator = validateApp()
 * const appValidator = validateApp({ baseUrl: 'http://localhost:9003' })
 * const appValidatorOptional = validateApp(undefined, { required: false })
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

    const verifiedApp = getValidatedAppFromLocals(req, appId)
    if (verifiedApp) {
      return next({ app: verifiedApp })
    }

    // 调用 auth-server 验证
    const result = await client.verifyApp(appId)

    if (!result.data?.valid || !result.data.app) {
      if (required) {
        const status = normalizeAuthFailureStatus(result.error?.code, 400)
        return Response.json({
          code: status,
          message: result.error?.message || result.data?.message || '无效的 app-id',
        }, { status })
      }
      // required: false 时也不注入无效的 app
      return next()
    }

    // 统一返回完整的 app 对象
    return next({ app: result.data.app })
  })
}

/**
 * 用户认证 + App 验证中间件（默认服务准入）
 *
 * 适合后台业务接口：要求用户已认证、app-id 有效，并在一次 JWT 验证中注入 userInfo 和 app。
 */
export function authenticateWithApp(options?: AuthMiddlewareOptions) {
  return withServiceAccess(authWithAppIdentity(resolveFactoryClient(options)))
}

/** 用户认证 + App 验证，跳过服务准入。 */
export function authenticateWithAppAllowWaitlisted(options?: AuthMiddlewareOptions) {
  return authWithAppIdentity(resolveFactoryClient(options))
}

// ============ Guards（守卫层）============
// 
// 守卫是轻量级检查，不发网络请求，只检查上下文条件
// 命名规范：require* = 要求某个条件满足

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

/**
 * 要求账号已开通当前 app 的服务
 *
 * 只读上下文、不发网络请求。用于在 *AllowWaitlisted 中间件放行的路由组里，
 * 对候补用户不应触达的单个接口重新收紧。
 *
 * @example
 * ```ts
 * // 组级放行候补用户，仅管理类接口要求已开通
 * middleware: [authWithAppAllowWaitlisted]
 * // 管理接口
 * middleware: [requireServiceAccess, requireApp]
 * ```
 */
export const requireServiceAccess = defineMiddleware(async (req, next) => {
  const ctx = getLocals<{ userInfo?: UserInfo }>(req)
  const denied = denyIfWaitlisted(ctx?.userInfo, true)
  if (denied) {
    return denied
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

/**
 * 认证用户并验证 App
 *
 * 语义化别名，内部调用 authenticateWithApp
 */
export function authApp(options?: AuthMiddlewareOptions) {
  return authenticateWithApp(options)
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

const authIdentity = mixedIdentity(getSharedClient)
const jwtAuthIdentity = jwtIdentity(getSharedClient)
const apiKeyAuthIdentity = apiKeyIdentity(getSharedClient)
const authWithAppIdentitySingleton = authWithAppIdentity(getSharedClient)

/** 预配置的混合认证中间件（懒加载，默认服务准入） */
export const auth = withServiceAccess(authIdentity)

/** 预配置的 JWT 认证中间件（懒加载，默认服务准入） */
export const jwtAuth = withServiceAccess(jwtAuthIdentity)

/** 预配置的 API Key 认证中间件（懒加载，默认服务准入） */
export const apiKeyAuth = withServiceAccess(apiKeyAuthIdentity)

/** 预配置的 App 验证中间件（懒加载） */
export const appValidator = defineMiddleware<ValidateAppContext>(async (req, next) => {
  const client = getSharedClient()
  const appId = req.headers.get('app-id')

  if (!appId) {
    return Response.json({ code: 400, message: '缺少必需的请求头: app-id' }, { status: 400 })
  }

  const verifiedApp = getValidatedAppFromLocals(req, appId)
  if (verifiedApp) {
    return next({ app: verifiedApp })
  }

  const result = await client.verifyApp(appId)
  if (!result.data?.valid || !result.data.app) {
    const status = normalizeAuthFailureStatus(result.error?.code, 400)
    return Response.json({
      code: status,
      message: result.error?.message || result.data?.message || '无效的 app-id',
    }, { status })
  }

  // 统一返回完整的 app 对象
  return next({ app: result.data.app })
})

/** 预配置的用户认证 + App 验证中间件（懒加载，默认服务准入） */
export const authWithApp = withServiceAccess(authWithAppIdentitySingleton)

// ============ 候补放行中间件 ============
//
// 与同名标准中间件同一套身份认证，只是不叠服务准入。
// 用于邀请制下候补用户同样必须可用的接口，例如兑换邀请码、提交开通申请、投诉举报。

/** 混合认证，允许候补用户 */
export const authAllowWaitlisted = authIdentity

/** JWT 认证，允许候补用户 */
export const jwtAuthAllowWaitlisted = jwtAuthIdentity

/** API Key 认证，允许候补用户 */
export const apiKeyAuthAllowWaitlisted = apiKeyAuthIdentity

/** 用户认证 + App 验证，允许候补用户 */
export const authWithAppAllowWaitlisted = authWithAppIdentitySingleton

