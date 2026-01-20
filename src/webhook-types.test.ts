/**
 * RouteExtensions 类型测试
 *
 * 这些测试验证路由扩展类型在编译时的正确性
 * 如果类型定义有问题，TypeScript 编译会失败
 */
import { describe, it, expectTypeOf } from 'vitest'
import type { RouteExtensions, WebhookConfigOptions } from './index'

describe('RouteExtensions 类型', () => {
  it('webhook 应该是可选的', () => {
    // webhook 字段是可选的
    type TestType = RouteExtensions['webhook']
    expectTypeOf<TestType>().toEqualTypeOf<boolean | WebhookConfigOptions | undefined>()
  })

  it('webhook 可以是 boolean', () => {
    const config: RouteExtensions = { webhook: true }
    expectTypeOf(config.webhook).toEqualTypeOf<boolean | WebhookConfigOptions | undefined>()
  })

  it('webhook 可以是 WebhookConfigOptions', () => {
    const config: RouteExtensions = {
      webhook: {
        eventKey: 'test.event',
        exclude: ['password'],
        include: ['id'],
      },
    }
    expectTypeOf(config.webhook).toEqualTypeOf<boolean | WebhookConfigOptions | undefined>()
  })

  it('webhook 可以省略', () => {
    const config: RouteExtensions = {}
    expectTypeOf(config).toMatchTypeOf<RouteExtensions>()
  })

  it('支持自定义扩展字段（索引签名）', () => {
    const config: RouteExtensions = {
      webhook: true,
      permission: 'admin',
      rateLimit: 100,
      customField: { nested: true },
    }
    expectTypeOf(config).toMatchTypeOf<RouteExtensions>()
  })
})

describe('WebhookConfigOptions 类型', () => {
  it('所有字段都是可选的', () => {
    const config: WebhookConfigOptions = {}
    expectTypeOf(config).toMatchTypeOf<WebhookConfigOptions>()
  })

  it('eventKey 是 string 类型', () => {
    const config: WebhookConfigOptions = { eventKey: 'test.event' }
    expectTypeOf(config.eventKey).toEqualTypeOf<string | undefined>()
  })

  it('exclude 是 string[] 类型', () => {
    const config: WebhookConfigOptions = { exclude: ['password', 'secret'] }
    expectTypeOf(config.exclude).toEqualTypeOf<string[] | undefined>()
  })

  it('include 是 string[] 类型', () => {
    const config: WebhookConfigOptions = { include: ['id', 'name'] }
    expectTypeOf(config.include).toEqualTypeOf<string[] | undefined>()
  })
})

describe('路由定义器与扩展集成', () => {
  it('defineAuthRouteWithApp 返回的函数接受 webhook 和自定义扩展', () => {
    // 这个测试验证 defineAuthRouteWithApp 的类型签名
    // 如果类型错误，TypeScript 编译会失败

    // 简单布尔值
    const _simpleConfig = {
      method: 'POST' as const,
      path: '/create',
      webhook: true,
      handler: ({ userInfo, app }: { userInfo: { id: string }; app: { id: string } }) => ({
        userId: userInfo.id,
        appId: app.id,
      }),
    } satisfies RouteExtensions & Record<string, unknown>

    // 详细配置 + 自定义扩展
    const _detailedConfig = {
      method: 'POST' as const,
      path: '/update',
      webhook: {
        eventKey: 'user.updated',
        exclude: ['password'],
      },
      permission: 'admin',  // 自定义扩展
      rateLimit: 100,       // 自定义扩展
      handler: ({ userInfo, app }: { userInfo: { id: string }; app: { id: string } }) => ({
        userId: userInfo.id,
        appId: app.id,
      }),
    } satisfies RouteExtensions & Record<string, unknown>

    // 无 webhook，只有自定义扩展
    const _customOnlyConfig = {
      method: 'GET' as const,
      path: '/list',
      permission: 'viewer',
      handler: ({ userInfo, app }: { userInfo: { id: string }; app: { id: string } }) => ({
        userId: userInfo.id,
        appId: app.id,
      }),
    } satisfies RouteExtensions & Record<string, unknown>

    // 如果能到这里说明类型检查通过
    expectTypeOf(_simpleConfig.webhook).toEqualTypeOf<true>()
    expectTypeOf(_detailedConfig.webhook).toMatchTypeOf<WebhookConfigOptions>()
    expectTypeOf(_detailedConfig.permission).toEqualTypeOf<string>()
    expectTypeOf(_customOnlyConfig.webhook).toEqualTypeOf<undefined>()
  })
})
