# @vafast/auth-middleware

Vafast 认证中间件 - 完整的 JWT/API Key 验证解决方案。

## 特点

- **开箱即用**：内置 auth-server 客户端，无需额外依赖
- **硬认证模式**：验证失败直接返回 401，需要认证就加中间件，不需要就不加
- **支持多种认证**：JWT、API Key、混合认证
- **语义化导出**：函数名清晰表达功能
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
AUTH_SERVICE_API_KEY_ID=ak_xxx
AUTH_SERVICE_API_KEY_SECRET=sk_xxx
```

```typescript
import { createAuth } from '@vafast/auth-middleware'

// 一行代码创建所有认证工具
const { auth, appValidator } = createAuth()

// 在路由中使用
export const routes = defineRoutes({
  prefix: '/api',
  routes: [
    // 需要认证的接口 - 加 auth 中间件
    defineRoute({
      method: 'GET',
      path: '/profile',
      middleware: [auth, appValidator],
      handler: async ({ userInfo }) => {
        return Response.json({ user: userInfo })
      },
    }),

    // 公开接口 - 不加中间件
    defineRoute({
      method: 'GET',
      path: '/public',
      handler: async () => {
        return Response.json({ message: 'Hello' })
      },
    }),
  ],
})
```

### 方式二：手动配置

```typescript
import { authenticateJwt, validateApp, requireUserAndApp } from '@vafast/auth-middleware'

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

### 方式三：零配置（推荐）

设置好环境变量后，直接导入预配置的中间件：

```typescript
import { auth, appValidator } from '@vafast/auth-middleware'

// 直接使用，无需括号
export const routes = defineRoutes([
  defineRoute({
    method: 'GET',
    path: '/profile',
    middleware: [auth, appValidator],
    handler: ({ userInfo }) => ({ user: userInfo }),
  }),
])
```

> 预配置中间件使用懒加载单例，首次请求时初始化，自动读取环境变量。

### 方式四：共享客户端实例

```typescript
import { createAuthClient, authenticateJwt, authenticateApiKey } from '@vafast/auth-middleware'

// 方式1：无参数，自动读取环境变量
const client = createAuthClient()

// 方式2：手动配置
const client = createAuthClient({
  baseUrl: 'http://localhost:9003',
  apiKeyId: 'ak_xxx',
  apiKeySecret: 'sk_xxx',
})

// 多个中间件共享同一客户端
const jwtAuth = authenticateJwt(client)
const apiKeyAuth = authenticateApiKey(client)

// 也可以直接调用客户端方法
const users = await client.getUsersBatch(['user1', 'user2'])
```

## 导出一览

### 中间件工厂函数

| 函数名 | 语义化别名 | 说明 |
|--------|-----------|------|
| `authenticate` | `authJwtAndApiKey` | JWT + API Key 混合认证 |
| `authenticateJwt` | `authJwt` | 仅 JWT 认证 |
| `authenticateApiKey` | `authApiKey` | 仅 API Key 认证 |
| `validateApp` | `validateAppId` | App ID 验证 |

### 预配置中间件一览

| 中间件 | 功能 |
|--------|------|
| `auth` | JWT + API Key 混合认证 |
| `jwtAuth` | 仅 JWT 认证 |
| `apiKeyAuth` | 仅 API Key 认证 |
| `appValidator` | 验证 app-id |

```typescript
import { auth, jwtAuth, apiKeyAuth, appValidator } from '@vafast/auth-middleware'

// 直接使用，无需括号
middleware: [auth, appValidator]
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
  requireUserAndApp,       // 需要登录 + App Guard
  requireApiKey,     // 需要 API Key Guard
  // 路由定义器（类型推断辅助）
  defineAuthRoute,         // { userInfo: UserInfo }
  defineOptionalAuthRoute, // { userInfo?: UserInfo }
  defineApiKeyRoute,       // { userInfo?, apiKey? }
  defineAuthRouteWithApp,  // { userInfo, app }
  defineRouteWithApp,      // { app }
  defineOptionalAuthRouteWithApp,  // { userInfo?, app }
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

### authenticateJwt / authJwt

JWT 认证中间件。

```typescript
import { authenticateJwt, authJwt } from '@vafast/auth-middleware'

// 方式1：无参数，自动读取环境变量
const jwtAuth = authenticateJwt()

// 方式2：手动配置
const jwtAuth = authenticateJwt({ baseUrl: 'http://localhost:9003' })

// 方式3：传入已创建的客户端
const client = createAuthClient()
const jwtAuth = authenticateJwt(client)
```

### authenticateApiKey / authApiKey

API Key 认证中间件。

```typescript
import { authenticateApiKey, authApiKey } from '@vafast/auth-middleware'

// 无参数调用
const apiKeyAuth = authenticateApiKey()
```

### authenticate / authJwtAndApiKey

混合认证中间件，自动识别 JWT 或 API Key。

```typescript
import { authenticate, authJwtAndApiKey } from '@vafast/auth-middleware'

// 无参数调用（推荐）
const auth = authenticate()
const auth = authJwtAndApiKey()  // 语义化别名
```

### validateApp / validateAppId

App ID 验证中间件。

```typescript
import { validateApp, validateAppId } from '@vafast/auth-middleware'

// 无参数调用
const appValidator = validateApp()

// 可选 app-id
const appValidatorOptional = validateApp(undefined, { required: false })
```

**选项：**
- `config?`: `AuthClientConfig | AuthClient` - 客户端配置或实例，不传则从环境变量读取
- `options.required?`: `boolean` - 是否必需，默认 true
- `options.verify?`: `boolean` - 是否网络验证，默认 true

### Guards

硬认证模式下，Guards 主要用于特殊场景：

```typescript
import { requireUser, requireApp, requireApiKey } from '@vafast/auth-middleware'

// requireUser - 检查 userInfo 是否存在（硬认证下通常不需要）
// requireApp - 检查 app/appId 是否存在（配合 validateAppId 使用）
// requireApiKey - 检查 apiKey 是否存在（用于要求必须是 API Key 认证，而非 JWT）
```

### 路由定义器（类型推断辅助）

```typescript
import {
  defineAuthRoute,           // { userInfo: UserInfo }
  defineOptionalAuthRoute,   // { userInfo?: UserInfo }
  defineApiKeyRoute,         // { userInfo?: UserInfo, apiKey?: ApiKeyInfo }
  defineAuthRouteWithApp,    // { userInfo: UserInfo, app: AppInfo }
  defineRouteWithApp,        // { app: AppInfo }
  defineOptionalAuthRouteWithApp,  // { userInfo?: UserInfo, app: AppInfo }
  defineFullAuthRoute,       // { userInfo: UserInfo, apiKey?: ApiKeyInfo, app: AppInfo }
} from '@vafast/auth-middleware'

// 使用示例
defineAuthRoute({
  method: 'GET',
  path: '/profile',
  middleware: [auth],  // 硬认证，userInfo 一定存在
  handler: ({ userInfo }) => {
    // userInfo 自动有正确的类型推断
    return { id: userInfo.id, email: userInfo.email }
  },
})

defineAuthRouteWithApp({
  method: 'POST',
  path: '/update',
  middleware: [auth, appValidator],  // 认证 + App 验证
  handler: ({ userInfo, app }) => {
    // userInfo 和 app 都有完整类型
    return { userId: userInfo.id, appId: app.id }
  },
})

// 可选认证 + App 验证（C端公开接口）
defineOptionalAuthRouteWithApp({
  method: 'POST',
  path: '/notices',
  middleware: [auth, appValidator],  // auth 失败不会报错，只是 userInfo 为 undefined
  handler: ({ userInfo, app }) => {
    if (userInfo) {
      // 已登录用户：返回个性化数据
      return { notices: [], personalized: true }
    } else {
      // 未登录用户：返回基础数据
      return { notices: [], personalized: false }
    }
  },
})

defineRouteWithApp({
  method: 'GET',
  path: '/app-info',
  middleware: [appValidator],  // 只需要 App 验证
  handler: ({ userInfo, app }) => {
    // userInfo 和 app 都有类型
    return { userId: userInfo.id, appId: app.id }
  },
})
```

## 认证流程

```
请求 → auth 中间件
     ↓
     提取 Authorization header
     ↓
     无 header → 返回 401
     ↓
     识别认证类型（JWT 或 API Key）
     ↓
     调用 auth-server 验证
     ↓
     验证失败 → 返回 401
     ↓
     验证成功 → 注入 userInfo/apiKey 到上下文
     ↓
     继续到 handler
```

**硬认证设计**：加了 `auth` 中间件就必须认证成功，不需要认证的路由不加中间件即可。

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
| AUTH_SERVICE_API_KEY_ID | 否 | 服务间通信 API Key ID |
| AUTH_SERVICE_API_KEY_SECRET | 否 | 服务间通信 API Key Secret |
| AUTH_API_TIMEOUT | 否 | 请求超时（毫秒） |

## 完整示例

### 方式一：使用 createAuth（推荐）

```typescript
// src/middleware/index.ts
import { createAuth } from '@vafast/auth-middleware'

export const {
  client: authClient,
  auth,
  appValidator,
} = createAuth()

// src/routes/users.ts
import { defineRoutes, defineRoute } from 'vafast'
import { auth, appValidator, authClient } from '../middleware'

export const userRoutes = defineRoutes({
  prefix: '/users',
  routes: [
    // 需要认证 - 加 auth 中间件
    defineRoute({
      method: 'GET',
      path: '/me',
      middleware: [auth, appValidator],
      handler: async ({ userInfo }) => {
        // userInfo 一定存在（硬认证）
        return Response.json({ user: userInfo })
      },
    }),

    // 公开接口 - 不加中间件
    defineRoute({
      method: 'GET',
      path: '/count',
      handler: async () => {
        return Response.json({ count: 100 })
      },
    }),
  ],
})
```

### 方式二：使用语义化别名

```typescript
// src/middleware/index.ts
import { 
  authJwtAndApiKey, 
  validateAppId, 
  requireApp 
} from '@vafast/auth-middleware'

const config = {
  baseUrl: process.env.AUTH_API_BASE_URL,
  apiKeyId: process.env.AUTH_SERVICE_API_KEY_ID,
  apiKeySecret: process.env.AUTH_SERVICE_API_KEY_SECRET,
}

// 导出配置好的中间件
export const auth = authJwtAndApiKey(config)       // JWT + API Key 混合认证（硬认证）
export const appValidator = validateAppId(config)  // App ID 验证

// Guards（仅在需要时使用）
export { requireApp } from '@vafast/auth-middleware'
```

## License

MIT
