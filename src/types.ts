import type { Context } from 'hono'
import ms from 'ms'

export type SignatureAlgorithm = keyof typeof AlgorithmTypes
export type CookiePrefixOptions = 'host' | 'secure'
export type JwtOpts = {
  /**
   * 颁发者，一般为域名
   * 例如：'hono.dev'
   * @default env.JWT_ISSUER || 'hono.dev'
   */
  issuer: string
  /**
   * 密钥，用于签名和验证JWT
   * @default env.JWT_SECRET
   */
  secret: string
  /**
   * 私有密钥，用于签名和验证JWT，默认与secret相同
   * @default env.JWT_SECRET_PRIVATE || secret
   */
  secretPrivate?: string
  /**
   * 签名算法，默认是HS256
   * @default 'HS256'
   */
  algorithm: SignatureAlgorithm
  /**
   * 过期时间，默认是1天
   * @default '1d'
   */
  expiresIn: number | ms.StringValue
  /**
   * 刷新过期时间，默认是7天
   * @default '7d'
   */
  expiresInRefresh: number | ms.StringValue
  /**
   * 是否默认暴露接口，默认是false，即所有接口都需要JWT认证
   * @default false
   */
  exposeDefault: boolean
  /**
   * 自定义header名称，默认是'Authorization'，例如改成 'x-custom-auth-header'
   * @default 'Authorization'
   */
  headerName: string
  /**
   * Cookie 配置，若配置则除了从header中获取token，还会从cookie中获取token
   * @default 'token'
   */
  cookie?:
    | string
    | {
        key: string
        secret?: string | BufferSource
        prefixOptions?: CookiePrefixOptions
      }
  /**
   * 自定义 token 获取，例如从请求体
   * @param c hono.Context
   * @returns token字符串或undefined
   */
  customParseToken?: (c: Context) => string | undefined
  /**
   * 当获取 token 失败进入此方法，例如个别接口希望暴露
   * @param c hono.Context
   * @param e { token }
   * @returns false拦截，true放行
   * @default false
   */
  interceptor: (
    c: Context,
    e: {
      token?: string
    },
  ) => boolean | Promise<boolean>
}

type BaseType = string | number | boolean

/**
 * 常用Jwt内容体
 */
export interface JwtContent {
  /**
   * Subject, 一般表示用户id
   */
  sub: string
  /**
   * 名称，姓名全称或用户名等等
   */
  name?: string
  /**
   * 昵称
   */
  nickname?: string
  /**
   * 头像url地址
   */
  picture?: string
  /**
   * 地址
   */
  address?: string
  /**
   * 性别
   */
  gender?: string
  /**
   * 邮箱
   */
  email?: string
  /**
   * 邮箱是否验证
   */
  email_verified?: boolean
  /**
   * 手机号
   */
  phone_number?: string
  /**
   * 手机号是否验证
   */
  phone_number_verified?: boolean
  /**
   * 角色
   */
  roles?: string[]
  /**
   * 是否refreshToken
   */
  rfh?: boolean
  /**
   * Issued At，签发时间戳
   */
  iat?: number
  /**
   * Expiration Time，过期时间戳
   */
  exp?: number
  /**
   * issuer 颁发者
   */
  iss?: string
  /**
   * Audience，接收方
   */
  aud?: string | string[]
  /**
   * Not Before，在此时间之前无效
   */
  nbf?: number
  /**
   * JWT ID，唯一标识符，可用于防止重放
   */
  jti?: string
  /**
   * 随机不重复字符串，如OIDC模式可能用到
   */
  nonce?: string
  /**
   * 扩展字段
   */
  [key: string]: BaseType | BaseType[] | undefined
}

/**
 * @module
 * JSON Web Algorithms (JWA)
 * https://datatracker.ietf.org/doc/html/rfc7518
 */
export declare enum AlgorithmTypes {
  HS256 = 'HS256',
  HS384 = 'HS384',
  HS512 = 'HS512',
  RS256 = 'RS256',
  RS384 = 'RS384',
  RS512 = 'RS512',
  PS256 = 'PS256',
  PS384 = 'PS384',
  PS512 = 'PS512',
  ES256 = 'ES256',
  ES384 = 'ES384',
  ES512 = 'ES512',
}
