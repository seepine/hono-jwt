import { describe, expect, it } from 'vitest'
import { jwtSign, jwtVerify } from '.'

describe('NotInit', async () => {
  it('base', async () => {
    try {
      console.log(jwtSign({ sub: '4' }, Date.now()))
    } catch (e: any) {
      expect(e.message).toBe('use jwtMiddleware first')
    }
    try {
      console.log(jwtVerify('token'))
    } catch (e: any) {
      expect(e.message).toBe('use jwtMiddleware first')
    }
  })
})
