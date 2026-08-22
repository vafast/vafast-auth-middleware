# @vafast/auth-middleware

对接 auth-server 的 JWT / API Key **硬认证**、`app-id` 校验、守卫与带类型的路由定义器。

硬认证：挂了就必须成功；失败直接 401/400。需要认证就挂，不需要就不挂。

完整文档：[Auth Middleware](https://vafast.dev/middleware/auth-middleware)

## 先搞清几个概念

### Bearer JWT vs API Key

都使用 `Authorization: Bearer <凭证>`，用凭证是否含 **`:`** 区分：

| 方式 | 凭证 | 行为 |
|------|------|------|
| JWT | 不含 `:` | `/verifyJwt`；可附带请求头 `app-id` |
| API Key | `id:secret` | `/verifyApiKey`；注入 `userInfo` + `apiKey` |

服务间调用 auth-server 用的 `AUTH_SERVICE_API_KEY_*` 与用户侧 Bearer API Key 是两套凭证。

### 失败码：401 vs 400

| 场景 | 状态码 |
|------|--------|
| 缺少/非法 Authorization、JWT/API Key 失败、账号禁用/删除 | **401** |
| 缺少/无效 `app-id` | **400** |
| 守卫无 `userInfo` / `apiKey` | **401** |
| 守卫无 `app` | **400** |
| 邀请制候补（`serviceAccess.granted === false`） | **403**，业务码 `4030001` |
| auth-server 超时 / 不可用 | **504** / **503** 风格 |

### `app-id` 多租户

`appValidator` / `authWithApp` 要求 `app-id` 请求头并校验后注入 `app`。

## 安装

```bash
npm install @vafast/auth-middleware
```

## 快速开始

```bash
AUTH_API_BASE_URL=http://localhost:9003
AUTH_SERVICE_API_KEY_ID=ak_xxx
AUTH_SERVICE_API_KEY_SECRET=sk_xxx
# 可选：AUTH_API_TIMEOUT=5000
```

```typescript
import { authWithApp, requireUser, defineAuthRouteWithApp } from '@vafast/auth-middleware'
import { defineRoute, defineRoutes } from 'vafast'

export const routes = defineRoutes([
  defineRoute({
    path: '/api',
    middleware: [authWithApp],
    children: [
      defineAuthRouteWithApp({
        method: 'GET',
        path: '/profile',
        middleware: [requireUser],
        handler: ({ userInfo, app }) => ({
          id: userInfo.id,
          appId: app.id,
        }),
      }),
    ],
  }),
])
```

## 用法

### 环境变量

| 变量 | 必需 | 说明 |
|------|------|------|
| `AUTH_API_BASE_URL` | 是* | auth-server 地址 |
| `AUTH_SERVICE_API_KEY_ID` | 否 | 服务间 API Key ID |
| `AUTH_SERVICE_API_KEY_SECRET` | 否 | 服务间 API Key Secret |
| `AUTH_API_TIMEOUT` | 否 | 超时毫秒，默认 `5000` |

\* 缺少 `baseUrl`（参数与环境变量都没有）时 `createAuthClient` 会抛错。

### 请求头

| Header | 说明 |
|--------|------|
| `Authorization: Bearer <jwt>` | JWT |
| `Authorization: Bearer <apiKeyId>:<secret>` | API Key |
| `app-id: <appId>` | 多租户 / `appValidator` / `authWithApp` |

### 预配置中间件（懒加载）

| 导出 | 说明 | 注入 |
|------|------|------|
| `auth` | JWT + API Key | `userInfo`（+ `apiKey`） |
| `jwtAuth` | 仅 JWT（含 `:` 非法） | `userInfo` |
| `apiKeyAuth` | 仅 API Key | `userInfo` + `apiKey` |
| `appValidator` | 必需 `app-id` | `app` |
| `authWithApp` | 用户 + app | `userInfo` + `app`（+ `apiKey`） |
| `authAllowWaitlisted` 等 | 同上，但跳过服务准入 | 同对应中间件 |

### 工厂

| 函数 | 别名 |
|------|------|
| `authenticate` | `authJwtAndApiKey` |
| `authenticateJwt` | `authJwt` |
| `authenticateApiKey` | `authApiKey` |
| `validateApp` | `validateAppId` |
| `authenticateWithApp` | `authApp` |
| `authenticateAllowWaitlisted` 等 | 工厂版候补放行，跳过服务准入 |

可传 `AuthClientConfig`、已有 `AuthClient`，或不传（读环境变量）。

`validateApp(config?, { required?, verify? })`：`required` / `verify` 默认均为 `true`；`verify: false` 只检查 header，注入最小化 app。

### 服务准入（邀请制，接入应用通用机制）

认证只回答「你是谁」。`auth` / `authenticate()` 默认再叠一层 `withServiceAccess`。

邀请制按 **app** 开关，不是按产品。auth-server 根据该 app 的 `inviteAccess.enabled` 下发 `userInfo.serviceAccess`：

- 未开启：`granted` 恒为 `true`，行为与未接入邀请制完全一致
- 已开启且 `granted === false`：返回 **403** + `4030001`，不走 401，避免前端误判登出
- 旧版 auth-server 不下发该字段时放行

候补用户也必须访问的接口（兑换邀请码、提交开通申请、投诉举报）用 `*AllowWaitlisted`；组内个别接口再挂 `requireServiceAccess` 收紧。自定义组合用 `withServiceAccess(identityMiddleware)`。

golds、sumusic、ONES 等接入应用升级本包后即可使用；每个 app 在空间设置里独立打开邀请制。

### 守卫（不发网络请求）

| 守卫 | 条件 | 失败 |
|------|------|------|
| `requireUser` | 有 `userInfo` | 401 |
| `requireApp` | 有 `app` | 400 |
| `requireApiKey` | 有 `apiKey` | 401 |
| `requireUserAndApp` | 两者都有 | 401 / 400 |
| `requireServiceAccess` | `serviceAccess.granted !== false` | 403 + `4030001` |

### 路由定义器

`defineAuthRoute`、`defineOptionalAuthRoute`、`defineApiKeyRoute`、`defineAuthRouteWithApp`、`defineRouteWithApp`、`defineOptionalAuthRouteWithApp`、`defineFullAuthRoute`

内置 `webhook?: boolean | { eventKey?, include?, exclude? }`（精简类型；完整能力见 `@vafast/webhook`）。

## API

### `createAuthClient(config?)`

| 字段 | 默认 | 说明 |
|------|------|------|
| `baseUrl` | `AUTH_API_BASE_URL` | 缺则抛错 |
| `apiKeyId` | `AUTH_SERVICE_API_KEY_ID` | 服务间 Bearer |
| `apiKeySecret` | `AUTH_SERVICE_API_KEY_SECRET` | 与 ID 组成 `id:secret` |
| `timeout` | `AUTH_API_TIMEOUT` 或 `5000` | 毫秒 |

客户端方法：`verifyJwt`、`verifyApiKey`、`verifyApp`、`getUsersBatch`、`searchUsers`、`getUsersStats`。

### `UserInfo` 组织相关字段（源码注释）

| 字段 | 含义 |
|------|------|
| `organizationId` | 组织成员所属组织；组织成员身份直接归属 organization |
| `accountType` | `organization_member` = 组织成员；`customer_user` = 客户应用终端用户 |
| `isOrgMemberAccess` | 组织成员跨 app 访问时为 `true` |
| `targetAppId` | 本次请求 `app-id` 指向的目标 app；跨 app 时与原始 `appId` 不同 |
| `accessMode` | `direct` 或 `org_member_delegate` |

另有基础字段：`id`、`appId`、`email`、`phone`、`avatar`、`status`、`roleId`、`nickname`、`verified`。  
`VerifiedUserInfo` 可带 `app?: AppInfo`。`AppInfo.extensions` 为 auth-server 维护的结构化扩展（如 organizationId）。

## 最佳实践

- 路由组挂 `authWithApp`，叶子挂 `requireUser` 等守卫。
- 公开接口不挂认证中间件。
- 多中间件共享同一 `createAuthClient()` 实例。
- 跨 app / 组织代理访问时读取 `accessMode` / `isOrgMemberAccess` / `targetAppId`。

## 注意事项

- 硬认证：没有「软登录失败继续」的预配置中间件。
- 预配置依赖环境变量；测试请用工厂 + 显式 client。
- `jwtAuth` 拒带 `:` 的 token；`apiKeyAuth` 要求 `id:secret`。
- 用户凭证失败多为 **401**；`app-id` 问题多为 **400**。
- 包内 `webhook` 类型只便于声明；实际分发需 `server.use(webhook(...))`。

## 相关链接

- [文档站点 · Auth Middleware](https://vafast.dev/middleware/auth-middleware)
- [@vafast/webhook](../vafast-webhook)
- [@vafast/jwt](../vafast-jwt)（本地签发/校验，不对接 auth-server）

## License

MIT
