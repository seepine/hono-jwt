# hono-jwt

[![npm version][npm-version-src]][npm-version-href]
[![npm downloads][npm-downloads-src]][npm-downloads-href]
[![bundle][bundle-src]][bundle-href]
[![License][license-src]][license-href]

针对 [Hono](https://hono.dev/) 的轻量级 JWT 中间件，提供 token 验证、签发与可配置的 token 提取策略（支持 Authorization header、cookie 与自定义拦截器）。

主要特性：

- 简单可配置的 JWT 验证中间件（`jwtMiddleware`）
- 提供 `sign` / `verify` 工具用于生成与校验 token
- 支持从 `Authorization` header、cookie 或自定义方法读取 token
- 支持 refresh token 签发、cookie 签名与过期时间配置
- 完整 TypeScript 类型声明（通过 `ContextVariableMap` 暴露 `jwt` 和 `user`）

---

## 快速上手

### 安装

```bash
npm install @seepine/hono-jwt
```

### 完整示例

```ts
import { Hono } from 'hono'
import { jwtMiddleware } from '@seepine/hono-jwt'
import { HTTPException } from 'hono/http-exception'

const app = new Hono()

// 1. 注册中间件
app.use(
  jwtMiddleware({
    issuer: 'hono.dev',
    secret: 'your-secret-key',
    // 拦截器，例如控制哪些接口可以直接放行
    interceptor: (c) => {
      // 放行登录接口
      if (c.req.path === '/oauth/token') {
        return true
      }
      return false
    },
  }),
)

// 2. 登录接口（无需 token，由 interceptor 放行）
app.post('/oauth/token', async (c) => {
  // TODO: 验证用户名密码...

  const payload = { sub: '1', name: 'Bob' }
  const now = Date.now()
  // 生成 token (第三个参数 true 表示同时生成 refresh_token)
  return c.json(c.var.jwt.sign(payload, now, true))
})

// 3. 刷新 token 接口
app.post('/oauth/refresh', async (c) => {
  const user = c.var.user
  // 检查是否是 refresh token (payload 中包含 rfh 字段)
  if (!user.rfh) {
    throw new HTTPException(401, { message: 'Invalid refresh token' })
  }
  // 签发新 token
  return c.json(
    c.var.jwt.sign({ sub: user.sub, name: user.name }, Date.now(), true),
  )
})

// 4. 受保护接口
app.get('/oauth/userinfo', async (c) => {
  // c.var.user 包含解析后的 token payload
  return c.json(c.var.user)
})

export default app
```

---

## API 与配置

`jwtMiddleware(jwtOpt?: Partial<JwtOpts>)` 接受以下常用配置项（详见 `src/types.ts`）：

- `secret`：用于签名与验证的密钥，支持环境变量 `JWT_SECRET`
- `issuer`：issuer 字段，默认 `hono.dev`，支持环境变量 `JWT_ISSUER`
- `expiresIn`：access token 的过期设置，默认 `1d`，支持环境变量 `JWT_EXPIRES_IN`
- `expiresInRefresh`：refresh token 的过期设置，默认 `7d`，支持环境变量 `JWT_EXPIRES_IN_REFRESH`
- `algorithm`：签名算法，默认 `HS256`，支持环境变量 `JWT_ALGORITHM`
- `secretPrivate`：当签名算法为 `RS256` 等非对称算法时，颁发token将会使用此私钥，secret则作为公钥，支持环境变量 `JWT_SECRET_PRIVATE`
- `headerName`：从请求头读取 token 的 header 名称（默认 `Authorization`）
- `cookie`：可配置 cookie key 或 cookie 签名参数，以从 cookie 读取 token
- `exposeDefault`：是否允许默认不强制拦截（开发或某些 endpoint 暴露使用）
- `interceptor`：当未提供 token 或 token 无效时调用，可用于实现匿名访问的放行逻辑
- `customParseToken`：自定义 token 提取策略，默认从 header cookie 中读取 token

中间件行为：

- 成功验证后，会通过 `ctx.set('user', payload)` 将解析后的 JWT 内容放到 context 中（`c.get('user')` 可取到）
- 中间件同时注入 `jwt` 实例（`c.get('jwt')`），可用于签发或校验 token
- 验证失败或未提供 token 且 `interceptor` 返回 false，会抛出 401 并设置 `WWW-Authenticate` 响应头

---

## 贡献

欢迎 PR、Issue 与改进建议。

<!-- Refs -->

[npm-version-src]: https://img.shields.io/npm/v/@seepine/hono-jwt
[npm-version-href]: https://www.npmjs.com/package/@seepine/hono-jwt
[npm-downloads-src]: https://img.shields.io/npm/dm/@seepine/hono-jwt
[npm-downloads-href]: https://npmjs.com/package/@seepine/hono-jwt
[bundle-src]: https://img.shields.io/bundlephobia/minzip/@seepine/hono-jwt
[bundle-href]: https://bundlephobia.com/result?p=@seepine/hono-jwt
[license-src]: https://img.shields.io/github/license/seepine/hono-jwt.svg
[license-href]: https://github.com/seepine/hono-jwt/blob/main/LICENSE
