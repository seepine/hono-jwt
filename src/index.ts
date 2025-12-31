import { createMiddleware } from 'hono/factory'
import type { JwtContent, JwtOpts } from './types'
import { sign, verify } from 'jsonwebtoken'
import { HTTPException } from 'hono/http-exception'
import type { Context } from 'hono'
import { getCookie, getSignedCookie } from 'hono/cookie'
import ms from 'ms'
export * from './types'

let opts: JwtOpts

/**
 * 生成jwtToken
 * @param jwtCtx jwt内容
 * @param issueAtUnix 颁发时间戳ms, Date.now() 或 dayjs().valueOf()
 * @param isRefresh 是否刷新token
 * @returns
 */
export const jwtSign = (
  jwtCtx: JwtContent,
  issueAtUnix: number,
  genRefresh = false,
) => {
  if (!opts) {
    throw new Error('use jwtMiddleware first')
  }
  const payload: Partial<JwtContent> = {
    ...jwtCtx,
    iat: Math.floor(issueAtUnix / 1000),
  }
  delete payload.exp
  delete payload.rfh
  delete payload.iss

  return {
    access_token: sign(
      {
        ...payload,
      },
      opts.secretPrivate || opts.secret,
      {
        issuer: opts.issuer,
        expiresIn: opts.expiresIn,
        algorithm: opts.algorithm,
      },
    ),
    refresh_token: genRefresh
      ? sign(
          {
            ...payload,
            rfh: true,
          },
          opts.secretPrivate || opts.secret,
          {
            issuer: opts.issuer,
            expiresIn: opts.expiresInRefresh,
            algorithm: opts.algorithm,
          },
        )
      : undefined,
    expires_in:
      typeof opts.expiresIn === 'number' ? opts.expiresIn : ms(opts.expiresIn),
    token_type: 'Bearer',
  }
}

export const jwtVerify = (
  token: string,
):
  | {
      verifyed: true
      payload: JwtContent
    }
  | {
      verifyed: false
      error: string
    } => {
  if (!opts) {
    throw new Error('use jwtMiddleware first')
  }
  try {
    var decoded: any = verify(token, opts.secret)
    return {
      verifyed: true,
      payload: decoded,
    }
  } catch (e: any) {
    let err = e.message
    switch (e.message) {
      case 'invalid signature':
        err = 'token不合法'
        break
      case 'jwt expired':
        err = '登录已过期'
        break
    }
    return {
      verifyed: false,
      error: err,
    }
  }
}

export type JwtSign = typeof jwtSign
export type JwtVerify = typeof jwtVerify
export type Jwt = {
  sign: JwtSign
  verify: JwtVerify
}

function unauthorizedResponse(opts: {
  ctx: Context
  error: string
  errDescription: string
  statusText?: string
}) {
  return new Response('Unauthorized', {
    status: 401,
    statusText: opts.statusText,
    headers: {
      'WWW-Authenticate': `Bearer realm="${opts.ctx.req.url}",error="${opts.error}",error_description="${opts.errDescription}"`,
    },
  })
}

const defaultInterceptor = () => {
  return false
}

export const parseJwtToken = async (ctx: Context) => {
  const credentials = ctx.req.raw.headers.get(opts.headerName)
  let token: string | undefined
  if (credentials) {
    const parts = credentials.split(/\s+/)
    if (parts.length === 1) {
      token = parts[0]
    } else if (parts.length === 2) {
      token = parts[1]
    } else {
      const errDescription = 'invalid credentials structure'
      throw new HTTPException(401, {
        message: errDescription,
        res: unauthorizedResponse({
          ctx,
          error: 'invalid_request',
          errDescription,
        }),
      })
    }
  } else if (opts.cookie) {
    if (typeof opts.cookie == 'string') {
      token = getCookie(ctx, opts.cookie)
    } else if (opts.cookie.secret) {
      if (opts.cookie.prefixOptions) {
        token = (
          await getSignedCookie(
            ctx,
            opts.cookie.secret,
            opts.cookie.key,
            opts.cookie.prefixOptions,
          )
        )?.toString()
      } else {
        token = (
          await getSignedCookie(ctx, opts.cookie.secret, opts.cookie.key)
        )?.toString()
      }
    } else {
      if (opts.cookie.prefixOptions) {
        token = getCookie(ctx, opts.cookie.key, opts.cookie.prefixOptions)
      } else {
        token = getCookie(ctx, opts.cookie.key)
      }
    }
  }
  return token
}

export const jwtMiddleware = (jwtOpt?: Partial<JwtOpts>) => {
  opts = {
    issuer: jwtOpt?.issuer ?? process.env.JWT_ISSUER ?? 'hono.dev',
    secret: jwtOpt?.secret ?? process.env.JWT_SECRET ?? '',
    expiresIn: jwtOpt?.expiresIn ?? (process.env.JWT_EXPIRES_IN as any) ?? '1d',
    expiresInRefresh:
      jwtOpt?.expiresInRefresh ??
      (process.env.JWT_EXPIRES_IN_REFRESH as any) ??
      '7d',
    algorithm:
      jwtOpt?.algorithm ?? (process.env.JWT_ALGORITHM as any) ?? 'HS256',
    secretPrivate: jwtOpt?.secretPrivate ?? process.env.JWT_SECRET_PRIVATE,
    exposeDefault: jwtOpt?.exposeDefault ?? false,
    headerName: jwtOpt?.headerName ?? 'Authorization',
    cookie: jwtOpt?.cookie,
    interceptor: jwtOpt?.interceptor ?? defaultInterceptor,
  }

  if (!opts.secret) {
    throw new Error('JWT auth middleware requires options for "secret"')
  }
  if (!opts.algorithm.startsWith('HS')) {
    if (!opts.secretPrivate) {
      throw new Error(
        `JWT auth middleware requires options for "secretPrivate" of ${opts.algorithm}`,
      )
    }
  }

  const jwtInst = {
    sign: jwtSign,
    verify: jwtVerify,
  }

  return createMiddleware(async (ctx, next) => {
    ctx.set('jwt', jwtInst)

    let token
    if (opts.customParseToken === undefined) {
      token = await parseJwtToken(ctx)
    } else {
      token = opts.customParseToken(ctx)
    }

    let user
    if (token) {
      const res = jwtInst.verify(token)
      if (res.verifyed) {
        user = res.payload
        ctx.set('user', user)
      }
    }

    // 找不到用户，且默认不暴露接口，进入验证器
    if (user === undefined && opts.exposeDefault !== true) {
      const res = await opts.interceptor(ctx, {
        token,
      })
      if (!res) {
        const errDescription = 'no authorization included in request'
        throw new HTTPException(401, {
          message: errDescription,
          res: unauthorizedResponse({
            ctx,
            error: 'invalid_request',
            errDescription,
          }),
        })
      }
    }
    await next()
  })
}

declare module 'hono' {
  interface ContextVariableMap {
    /**
     * JSON Web Token 实例，包含 sign 和 verify 方法
     */
    jwt: Jwt
    /**
     * 用户信息，非空安全，例如若接口不需要鉴权，可能为 undefined
     */
    user: JwtContent
  }
}
