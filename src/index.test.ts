import { describe, expect, it } from 'vitest'
import { createMiddleware } from 'hono/factory'
import { Hono } from 'hono'
import { jwtMiddleware } from '.'
import { testClient } from 'hono/testing'
import { HTTPException } from 'hono/http-exception'
import { routePath } from 'hono/route'

describe('HS256', async () => {
  const app = new Hono()
    .use(
      jwtMiddleware({
        secret: '123456',
        interceptor: (c) => {
          if (routePath(c, -1) === '/*') {
            throw new HTTPException(404, {
              message: 'Not Found',
            })
          }
          // 放行登录接口
          if (c.req.path === '/oauth/token') {
            return true
          }
          return false
        },
      }),
    )
    .use(
      createMiddleware(async (_, next) => {
        console.log('custom middleware in')
        await next()
        console.log('custom middleware out')
      }),
    )
    .post('/oauth/token', async (c) => {
      return c.json(
        c.var.jwt.sign({ sub: '1', name: 'Alex' }, Date.now(), true),
      )
    })
    .post('/oauth/refresh', async (c) => {
      const userinfo = c.var.user
      if (!userinfo.rfh) {
        throw new HTTPException(401, { message: 'invalid_request' })
      }
      return c.json(c.var.jwt.sign(userinfo, Date.now(), true))
    })
    .get('/oauth/userinfo', async (c) => {
      return c.json(c.var.user)
    })

  const client = testClient(app)

  it('base', async () => {
    const tokenResp = await client.oauth.token.$post()
    expect(tokenResp).not.toBeNull()
    expect(tokenResp.status).toBe(200)
    const tokenInfo = await tokenResp.json()
    console.log(tokenInfo)
    expect(tokenInfo.access_token).not.toBeUndefined()
    expect(tokenInfo.refresh_token).not.toBeUndefined()

    const userinfoResp = await client.oauth.userinfo.$get(undefined, {
      headers: {
        Authorization: `Bearer ${tokenInfo.access_token}`,
      },
    })
    expect(userinfoResp).not.toBeNull()
    expect(userinfoResp.status).toBe(200)
    const userinfo = await userinfoResp.json()
    console.log(userinfo)
    expect(userinfo.sub).toBe('1')

    await new Promise((RES) => setTimeout(RES, 1200))
    const refreshResp = await client.oauth.refresh.$post(undefined, {
      headers: {
        Authorization: `Bearer ${tokenInfo.refresh_token}`,
      },
    })
    expect(refreshResp).not.toBeNull()
    expect(refreshResp.status).toBe(200)
    const refreshInfo = await refreshResp.json()
    expect(refreshInfo.access_token).not.toBeUndefined()
    expect(refreshInfo.refresh_token).not.toBeUndefined()
    expect(refreshInfo.access_token).not.toBe(tokenInfo.access_token)
  })

  it('invalid token', async () => {
    const userinfoResp = await client.oauth.userinfo.$get(undefined, {
      headers: {
        Authorization: `Bearer 123`,
      },
    })
    expect(userinfoResp).not.toBeNull()
    expect(userinfoResp.status).toBe(401)
  })
})

const es256PublicKey = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEChkkirRDX7M27QkNmYNjrIL+yCu8
IAT11lzpKGOnc+vCc6FFZRPJqAKdeKR1SOwoV/DlBI8bvNWqZ0Sfp33rGQ==
-----END PUBLIC KEY-----
`
const es256PrivateKey = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg3TgslWZewOEr8Pps
Ey6hdttQ9vRRGztTYd5aG/rlGfuhRANCAAQKGSSKtENfszbtCQ2Zg2Osgv7IK7wg
BPXWXOkoY6dz68JzoUVlE8moAp14pHVI7ChX8OUEjxu81apnRJ+nfesZ
-----END PRIVATE KEY-----
`
describe('ES256', async () => {
  const app = new Hono()
    .use(
      jwtMiddleware({
        secret: es256PublicKey,
        secretPrivate: es256PrivateKey,
        algorithm: 'ES256',
        interceptor: (c) => {
          return c.req.path === '/oauth/token'
        },
        expiresIn: '1m',
        expiresInRefresh: '1h',
      }),
    )
    .post('/oauth/token', async (c) => {
      return c.json(c.var.jwt.sign({ sub: '2', name: 'Bob' }, Date.now(), true))
    })
    .get('/oauth/userinfo', async (c) => {
      return c.json(c.var.user)
    })

  const client = testClient(app)

  it('base', async () => {
    const tokenResp = await client.oauth.token.$post()
    expect(tokenResp).not.toBeNull()
    expect(tokenResp.status).toBe(200)
    const tokenInfo = await tokenResp.json()
    console.log(tokenInfo)
    expect(tokenInfo.access_token).not.toBeUndefined()
    expect(tokenInfo.refresh_token).not.toBeUndefined()

    const userinfoResp = await client.oauth.userinfo.$get(undefined, {
      headers: {
        Authorization: `Bearer ${tokenInfo.access_token}`,
      },
    })
    expect(userinfoResp).not.toBeNull()
    expect(userinfoResp.status).toBe(200)
    const userinfo = await userinfoResp.json()
    console.log(userinfo)
    expect(userinfo.sub).toBe('2')
  })
})

describe('From Cookie', async () => {
  const app = new Hono()
    .use(
      jwtMiddleware({
        secret: '123456',
        cookie: 'token',
        interceptor: (c) => {
          return c.req.path === '/oauth/token'
        },
      }),
    )
    .post('/oauth/token', async (c) => {
      return c.json(c.var.jwt.sign({ sub: '3', name: 'Charlie' }, Date.now()))
    })
    .get('/oauth/userinfo', async (c) => {
      return c.json(c.var.user)
    })

  const client = testClient(app)

  it('base', async () => {
    const tokenResp = await client.oauth.token.$post()
    expect(tokenResp).not.toBeNull()
    expect(tokenResp.status).toBe(200)
    const tokenInfo = await tokenResp.json()
    console.log(tokenInfo)
    expect(tokenInfo.access_token).not.toBeUndefined()
    expect(tokenInfo.refresh_token).toBeUndefined()

    const userinfoResp = await client.oauth.userinfo.$get(undefined, {
      headers: {
        Cookie: `token=${tokenInfo.access_token}`,
      },
    })
    expect(userinfoResp).not.toBeNull()
    expect(userinfoResp.status).toBe(200)
    const userinfo = await userinfoResp.json()
    console.log(userinfo)
    expect(userinfo.sub).toBe('3')
  })
})
