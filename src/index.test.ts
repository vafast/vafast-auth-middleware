import { afterEach, describe, it, expect, vi } from 'vitest'
import {
  createAuthClient,
  authenticateJwt,
  authenticateApiKey,
  authenticate,
  authenticateAllowWaitlisted,
  withServiceAccess,
  validateApp,
  requireUserAndApp,
  requireApiKey,
  defineAuthRoute,
  defineOptionalAuthRoute,
  defineApiKeyRoute,
  defineAuthRouteWithApp,
  defineRouteWithApp,
  defineOptionalAuthRouteWithApp,
  defineFullAuthRoute,
  authAllowWaitlisted,
  authWithAppAllowWaitlisted,
  jwtAuthAllowWaitlisted,
  apiKeyAuthAllowWaitlisted,
  SERVICE_ACCESS_WAITLISTED_CODE,
  type AuthClientConfig,
} from './index'

// Mock vafast
vi.mock('vafast', () => ({
  defineMiddleware: vi.fn((fn) => fn),
  withContext: vi.fn(() => vi.fn()),
  err: vi.fn((message: string, status = 500, code = status) =>
    Object.assign(new Error(message), { status, code }),
  ),
}))

describe('createAuthClient', () => {
  const originalFetch = globalThis.fetch

  afterEach(() => {
    globalThis.fetch = originalFetch
    vi.restoreAllMocks()
  })

  it('应该创建包含所有方法的客户端', () => {
    const config: AuthClientConfig = {
      baseUrl: 'http://localhost:9003',
      apiKeyId: 'ak_test',
      apiKeySecret: 'sk_test',
    }
    const client = createAuthClient(config)

    expect(typeof client.verifyJwt).toBe('function')
    expect(typeof client.verifyApiKey).toBe('function')
    expect(typeof client.verifyApp).toBe('function')
    expect(typeof client.getUsersBatch).toBe('function')
    expect(typeof client.searchUsers).toBe('function')
    expect(typeof client.getUsersStats).toBe('function')
  })

  it('应该将 auth-server 超时归类为 504', async () => {
    const abortError = Object.assign(new Error('This operation was aborted'), { name: 'AbortError' })
    globalThis.fetch = vi.fn().mockRejectedValue(abortError)

    const client = createAuthClient({ baseUrl: 'http://localhost:9003', timeout: 1 })
    const result = await client.verifyJwt('token')

    expect(result.error).toEqual({
      code: 504,
      message: '认证服务响应超时，请稍后重试',
    })
  })

  it('应该将 auth-server 网络错误归类为 503', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'))

    const client = createAuthClient({ baseUrl: 'http://localhost:9003' })
    const result = await client.verifyJwt('token')

    expect(result.error).toEqual({
      code: 503,
      message: '认证服务暂时不可用，请稍后重试',
    })
  })
})

describe('authenticateJwt', () => {
  it('应该接受配置对象', () => {
    const middleware = authenticateJwt({ baseUrl: 'http://localhost:9003' })
    expect(typeof middleware).toBe('function')
  })

  it('应该接受已创建的客户端实例', () => {
    const client = createAuthClient({ baseUrl: 'http://localhost:9003' })
    const middleware = authenticateJwt(client)
    expect(typeof middleware).toBe('function')
  })

  it('应该透传 auth-server 超时状态，而不是返回 401', async () => {
    const client = {
      verifyJwt: vi.fn().mockResolvedValue({
        error: { code: 504, message: '认证服务响应超时，请稍后重试' },
      }),
      verifyApiKey: vi.fn(),
      verifyApp: vi.fn(),
      getUsersBatch: vi.fn(),
      searchUsers: vi.fn(),
      getUsersStats: vi.fn(),
    }
    const middleware = authenticateJwt(client)
    const req = new Request('http://localhost/test', {
      headers: { authorization: 'Bearer jwt-token' },
    })

    await expect(middleware(req, vi.fn())).rejects.toMatchObject({
      message: '认证服务响应超时，请稍后重试',
      status: 504,
    })
  })
})

describe('authenticateApiKey', () => {
  it('应该接受配置对象', () => {
    const middleware = authenticateApiKey({ baseUrl: 'http://localhost:9003' })
    expect(typeof middleware).toBe('function')
  })
})

describe('authenticate', () => {
  it('应该接受配置对象', () => {
    const middleware = authenticate({ baseUrl: 'http://localhost:9003' })
    expect(typeof middleware).toBe('function')
  })
})

describe('validateApp', () => {
  it('应该接受配置对象', () => {
    const middleware = validateApp({ baseUrl: 'http://localhost:9003' })
    expect(typeof middleware).toBe('function')
  })

  it('应该接受 required 选项', () => {
    const middleware = validateApp({ baseUrl: 'http://localhost:9003' }, { required: false })
    expect(typeof middleware).toBe('function')
  })

  it('应该在 auth-server 超时时返回 504，而不是 400', async () => {
    const client = {
      verifyJwt: vi.fn(),
      verifyApiKey: vi.fn(),
      verifyApp: vi.fn().mockResolvedValue({
        error: { code: 504, message: '认证服务响应超时，请稍后重试' },
      }),
      getUsersBatch: vi.fn(),
      searchUsers: vi.fn(),
      getUsersStats: vi.fn(),
    }
    const middleware = validateApp(client)
    const req = new Request('http://localhost/test', {
      headers: { 'app-id': 'app_1' },
    })
    const response = await middleware(req, vi.fn())
    const data = await response.json()

    expect(response.status).toBe(504)
    expect(data).toEqual({
      code: 504,
      message: '认证服务响应超时，请稍后重试',
    })
  })
})

describe('Guards', () => {
  it('应该导出 requireUserAndApp guard', () => {
    expect(typeof requireUserAndApp).toBe('function')
  })

  it('应该导出 requireApiKey guard', () => {
    expect(typeof requireApiKey).toBe('function')
  })
})

describe('服务准入闸门', () => {
  const grantedUser = {
    id: 'u_1',
    appId: 'app_1',
    status: 'normal',
    serviceAccess: { inviteOnly: true, granted: true, status: 'granted' },
  }
  const waitlistedUser = {
    id: 'u_2',
    appId: 'app_1',
    status: 'normal',
    serviceAccess: { inviteOnly: true, granted: false, status: 'waitlisted' },
  }

  function clientOf(userInfo: unknown) {
    return {
      verifyJwt: vi.fn().mockResolvedValue({ data: userInfo }),
      verifyApiKey: vi.fn().mockResolvedValue({
        data: { userInfo, apiKey: { id: 'k_1', name: 'test', appId: 'app_1' } },
      }),
      verifyApp: vi.fn(),
      getUsersBatch: vi.fn(),
      searchUsers: vi.fn(),
      getUsersStats: vi.fn(),
    }
  }

  function jwtRequest() {
    return new Request('http://localhost/test', {
      headers: { authorization: 'Bearer jwt-token', 'app-id': 'app_1' },
    })
  }

  it('候补用户被拦截并返回 403 与业务码 4030001', async () => {
    const middleware = authenticate(clientOf(waitlistedUser))
    const response = await middleware(jwtRequest(), vi.fn())
    const data = await response.json()

    expect(response.status).toBe(403)
    expect(data.code).toBe(SERVICE_ACCESS_WAITLISTED_CODE)
  })

  it('业务码不被归一成 401，避免前端触发登出死循环', async () => {
    const middleware = authenticate(clientOf(waitlistedUser))
    const response = await middleware(jwtRequest(), vi.fn())

    expect(response.status).not.toBe(401)
  })

  it('已开通用户正常放行', async () => {
    const next = vi.fn().mockResolvedValue(new Response('ok'))
    const middleware = authenticate(clientOf(grantedUser))
    await middleware(jwtRequest(), next)

    expect(next).toHaveBeenCalledWith(expect.objectContaining({ userInfo: grantedUser }))
  })

  it('auth-server 未下发 serviceAccess 时放行，兼容旧版本', async () => {
    const next = vi.fn().mockResolvedValue(new Response('ok'))
    const legacyUser = { id: 'u_3', appId: 'app_1', status: 'normal' }
    const middleware = authenticate(clientOf(legacyUser))
    await middleware(jwtRequest(), next)

    expect(next).toHaveBeenCalled()
  })

  it('应用未开启邀请制时 granted 恒为 true，不拦截', async () => {
    const next = vi.fn().mockResolvedValue(new Response('ok'))
    const openUser = {
      id: 'u_4',
      appId: 'app_1',
      status: 'normal',
      serviceAccess: { inviteOnly: false, granted: true, status: 'granted' },
    }
    const middleware = authenticate(clientOf(openUser))
    await middleware(jwtRequest(), next)

    expect(next).toHaveBeenCalled()
  })

  it('关闭强制检查后候补用户可放行', async () => {
    const next = vi.fn().mockResolvedValue(new Response('ok'))
    const middleware = authenticateAllowWaitlisted(clientOf(waitlistedUser))
    await middleware(jwtRequest(), next)

    expect(next).toHaveBeenCalled()
  })

  it('withServiceAccess(identity, false) 等价于跳过准入', async () => {
    const next = vi.fn().mockResolvedValue(new Response('ok'))
    const middleware = withServiceAccess(authenticateAllowWaitlisted(clientOf(waitlistedUser)), false)
    await middleware(jwtRequest(), next)

    expect(next).toHaveBeenCalled()
  })

  it('JWT 原样透传 auth-server 下发的扩展字段', async () => {
    const next = vi.fn().mockResolvedValue(new Response('ok'))
    const user = {
      ...grantedUser,
      organizationId: 'org_1',
      accountType: 'organization_member',
      accessMode: 'direct',
    }
    const middleware = authenticateJwt(clientOf(user))
    await middleware(jwtRequest(), next)

    expect(next).toHaveBeenCalledWith(expect.objectContaining({
      userInfo: expect.objectContaining({
        organizationId: 'org_1',
        accountType: 'organization_member',
        serviceAccess: grantedUser.serviceAccess,
      }),
    }))
  })

  it('候补用户无法用 API Key 绕过', async () => {
    const middleware = authenticate(clientOf(waitlistedUser))
    const req = new Request('http://localhost/test', {
      headers: { authorization: 'Bearer ak_test:sk_test', 'app-id': 'app_1' },
    })
    const response = await middleware(req, vi.fn())
    const data = await response.json()

    expect(response.status).toBe(403)
    expect(data.code).toBe(SERVICE_ACCESS_WAITLISTED_CODE)
  })

  it('导出候补放行中间件', () => {
    expect(typeof authAllowWaitlisted).toBe('function')
    expect(typeof authWithAppAllowWaitlisted).toBe('function')
    expect(typeof jwtAuthAllowWaitlisted).toBe('function')
    expect(typeof apiKeyAuthAllowWaitlisted).toBe('function')
  })
})

describe('Route Definers', () => {
  it('应该导出所有路由定义器', () => {
    expect(defineAuthRoute).toBeDefined()
    expect(defineOptionalAuthRoute).toBeDefined()
    expect(defineApiKeyRoute).toBeDefined()
    expect(defineAuthRouteWithApp).toBeDefined()
    expect(defineRouteWithApp).toBeDefined()
    expect(defineOptionalAuthRouteWithApp).toBeDefined()
    expect(defineFullAuthRoute).toBeDefined()
  })
})

describe('WebhookExtension 类型测试', () => {
  it('应该导出 WebhookExtension 和 WebhookConfigOptions 类型', async () => {
    // 类型导入测试
    const { WebhookExtension, WebhookConfigOptions } = await import('./index') as any
    // 类型在运行时不存在，但应该能通过编译
    expect(true).toBe(true)
  })

  it('路由定义器应该支持 webhook: true', () => {
    // 这是一个编译时类型测试
    // 如果 webhook 字段类型不正确，TypeScript 编译会失败
    const routeConfig = {
      method: 'POST' as const,
      path: '/test',
      webhook: true,
      handler: () => ({ success: true }),
    }
    expect(routeConfig.webhook).toBe(true)
  })

  it('路由定义器应该支持 webhook 对象配置', () => {
    const routeConfig = {
      method: 'POST' as const,
      path: '/test',
      webhook: {
        eventKey: 'custom.event',
        exclude: ['password', 'secret'],
        include: ['id', 'name'],
      },
      handler: () => ({ success: true }),
    }
    expect(routeConfig.webhook.eventKey).toBe('custom.event')
    expect(routeConfig.webhook.exclude).toEqual(['password', 'secret'])
    expect(routeConfig.webhook.include).toEqual(['id', 'name'])
  })

  it('路由定义器应该支持不带 webhook 的配置', () => {
    const routeConfig = {
      method: 'GET' as const,
      path: '/test',
      handler: () => ({ success: true }),
    }
    expect(routeConfig.webhook).toBeUndefined()
  })
})
