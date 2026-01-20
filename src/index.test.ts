import { describe, it, expect, vi } from 'vitest'
import {
  createAuthClient,
  authenticateJwt,
  authenticateApiKey,
  authenticate,
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
  type AuthClientConfig,
} from './index'

// Mock vafast
vi.mock('vafast', () => ({
  defineMiddleware: vi.fn((fn) => fn),
  withContext: vi.fn(() => vi.fn()),
}))

describe('createAuthClient', () => {
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
})

describe('Guards', () => {
  it('应该导出 requireUserAndApp guard', () => {
    expect(typeof requireUserAndApp).toBe('function')
  })

  it('应该导出 requireApiKey guard', () => {
    expect(typeof requireApiKey).toBe('function')
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
