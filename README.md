# @vafast/auth-middleware

Vafast 认证中间件 - 完整的 JWT/API Key 验证解决方案。

## 特点

- **开箱即用**：内置 auth-server 客户端，无需额外依赖
- **软认证模式**：验证失败不阻塞请求，让后续 guard 决定是否拒绝
- **支持多种认证**：JWT、API Key、混合认证
- **环境变量配置**：一行代码完成配置
- **零外部依赖**：仅依赖 `vafast` 框架和原生 `fetch`

## 安装

```bash
npm install @vafast/auth-middleware
```

## 快速开始

### 方式一：使用环境变量（推荐）

```bash
# .env
AUTH_API_BASE_URL=http://localhost:9003
API_KEY_ID=ak_xxx
API_KEY_SECRET=sk_xxx
```

```typescript
import { createAuth } from '@vafast/auth-middleware'

// 一行代码创建所有认证工具
const { auth, appValidator, requireAuth } = createAuth()

// 在路由中使用
export const routes = defineRoutes({
  prefix: '/api',
  middleware: [auth, appValidator],
  routes: [
    defineRoute({
      method: 'GET',
      path: '/profile',
      middleware: [requireAuth],
      handler: async ({ userInfo }) => {
        return Response.json({ user: userInfo })
      },
    }),
  ],
})
```

### 方式二：手动配置

```typescript
import { authenticateJwt, validateApp, requireAuth } from '@vafast/auth-middleware'

const jwtAuth = authenticateJwt({
  client: {
    baseUrl: 'http://localhost:9003',
    apiKeyId: 'ak_xxx',
    apiKeySecret: 'sk_xxx',
  },
})

const appValidator = validateApp({
  client: {
    baseUrl: 'http://localhost:9003',
  },
  required: true,
})
```

### 方式三：共享客户端实例

```typescript
import { createAuthClient, authenticateJwt, authenticateApiKey } from '@vafast/auth-middleware'

// 创建共享客户端
const client = createAuthClient({
  baseUrl: 'http://localhost:9003',
  apiKeyId: 'ak_xxx',
  apiKeySecret: 'sk_xxx',
})

// 多个中间件共享同一客户端
const jwtAuth = authenticateJwt({ client })
const apiKeyAuth = authenticateApiKey({ client })

// 也可以直接调用客户端方法
const users = await client.getUsersBatch(['user1', 'user2'])
```

## API 参考

### createAuth(configOverrides?)

从环境变量创建完整的认证工具集。

```typescript
const {
  client,            // AuthClient 实例
  jwtAuth,           // JWT 认证中间件
  apiKeyAuth,        // API Key 认证中间件
  auth,              // 混合认证中间件
  appValidator,      // App 验证（required: true）
  appValidatorOptional, // App 验证（required: false）
  requireAuth,       // 需要登录 Guard
  requireApiKey,     // 需要 API Key Guard
  // 路由定义器（类型推断辅助）
  defineAuthRoute,         // { userInfo: UserInfo }
  defineOptionalAuthRoute, // { userInfo?: UserInfo }
  defineApiKeyRoute,       // { userInfo?, apiKey? }
  defineAuthRouteWithApp,  // { userInfo, app }
  defineRouteWithApp,      // { app }
  defineFullAuthRoute,     // { userInfo, apiKey?, app }
} = createAuth()
```

### createAuthClient(config)

创建 auth-server 客户端。

```typescript
interface AuthClientConfig {
  baseUrl: string          // auth-server 地址
  apiKeyId?: string        // 服务间通信 API Key ID
  apiKeySecret?: string    // 服务间通信 API Key Secret
  timeout?: number         // 请求超时（毫秒），默认 5000
}

const client = createAuthClient({
  baseUrl: 'http://localhost:9003',
  apiKeyId: 'ak_xxx',
  apiKeySecret: 'sk_xxx',
})

// 客户端方法
await client.verifyJwt(token, appId?)
await client.verifyApiKey(apiKeyId, secretKey)
await client.verifyApp(appId)
await client.getUsersBatch(userIds)
await client.searchUsers({ keyword, appId, current, pageSize })
await client.getUsersStats({ appId, startTime, endTime })
```

### authenticateJwt(options)

JWT 认证中间件。

```typescript
const jwtAuth = authenticateJwt({
  client: AuthClientConfig | AuthClient,
  debug?: boolean,  // 默认 false
})
```

### authenticateApiKey(options)

API Key 认证中间件。

```typescript
const apiKeyAuth = authenticateApiKey({
  client: AuthClientConfig | AuthClient,
  debug?: boolean,
})
```

### authenticate(options)

混合认证中间件，自动识别 JWT 或 API Key。

```typescript
const auth = authenticate({
  client: AuthClientConfig | AuthClient,
  debug?: boolean,
})
```

### validateApp(options)

App 验证中间件。

```typescript
const appValidator = validateApp({
  client: AuthClientConfig | AuthClient,
  required?: boolean,  // 默认 true
  debug?: boolean,
})
```

### Guards

```typescript
import { requireAuth, requireApiKey } from '@vafast/auth-middleware'

// requireAuth - 检查 userInfo 是否存在
// requireApiKey - 检查 apiKey 是否存在
```

### 路由定义器（类型推断辅助）

```typescript
import {
  defineAuthRoute,           // { userInfo: UserInfo }
  defineOptionalAuthRoute,   // { userInfo?: UserInfo }
  defineApiKeyRoute,         // { userInfo?: UserInfo, apiKey?: ApiKeyInfo }
  defineAuthRouteWithApp,    // { userInfo: UserInfo, app: AppInfo }
  defineRouteWithApp,        // { app: AppInfo }
  defineFullAuthRoute,       // { userInfo: UserInfo, apiKey?: ApiKeyInfo, app: AppInfo }
} from '@vafast/auth-middleware'

// 使用示例
defineAuthRoute({
  method: 'GET',
  path: '/profile',
  middleware: [auth, requireAuth],
  handler: ({ userInfo }) => {
    // userInfo 自动有正确的类型推断
    return { id: userInfo.id, email: userInfo.email }
  },
})

defineAuthRouteWithApp({
  method: 'POST',
  path: '/update',
  middleware: [auth, appValidator, requireAuth],
  handler: ({ userInfo, app }) => {
    // userInfo 和 app 都有类型
    return { userId: userInfo.id, appId: app.id }
  },
})
```

## 认证流程

```
请求 → authenticate 中间件
     ↓
     提取 Authorization header
     ↓
     识别认证类型（JWT 或 API Key）
     ↓
     调用 auth-server 验证
     ↓
     成功：注入 userInfo/apiKey 到上下文
     失败：继续执行（软认证）
     ↓
     requireAuth/requireApiKey guard
     ↓
     无权限：返回 401
     有权限：继续到 handler
```

## 上下文类型

```typescript
// JWT 认证后
interface { userInfo?: UserInfo }

// API Key 认证后
interface { userInfo?: UserInfo; apiKey?: ApiKeyInfo }

// App 验证后
interface { app?: AppInfo }
```

## 环境变量

| 变量名 | 必需 | 说明 |
|--------|------|------|
| AUTH_API_BASE_URL | 是 | auth-server 地址 |
| API_KEY_ID | 否 | 服务间通信 API Key ID |
| API_KEY_SECRET | 否 | 服务间通信 API Key Secret |
| AUTH_API_TIMEOUT | 否 | 请求超时（毫秒） |

## 完整示例

```typescript
// src/middleware/auth.ts
import { createAuth } from '@vafast/auth-middleware'

export const {
  client: authClient,
  auth,
  appValidator,
  requireAuth,
  requireApiKey,
} = createAuth()

// src/routes/users.ts
import { defineRoutes, defineRoute } from 'vafast'
import { auth, appValidator, requireAuth, authClient } from '../middleware/auth'

export const userRoutes = defineRoutes({
  prefix: '/users',
  middleware: [auth, appValidator],
  routes: [
    // 需要登录
    defineRoute({
      method: 'GET',
      path: '/me',
      middleware: [requireAuth],
      handler: async ({ userInfo }) => {
        return Response.json({ user: userInfo })
      },
    }),

    // 公开接口（可选登录）
    defineRoute({
      method: 'GET',
      path: '/public',
      handler: async ({ userInfo }) => {
        return Response.json({ 
          loggedIn: !!userInfo,
          user: userInfo || null,
        })
      },
    }),

    // 需要 API Key
    defineRoute({
      method: 'POST',
      path: '/batch',
      middleware: [requireApiKey],
      handler: async ({ apiKey }, req) => {
        const { userIds } = await req.json()
        const result = await authClient.getUsersBatch(userIds)
        return Response.json(result)
      },
    }),
  ],
})
```

## License

MIT
