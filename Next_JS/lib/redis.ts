// Singleton Redis client for Next.js.
// The dev hot-reload would create many connections without the global singleton.

import Redis from 'ioredis'
import { createHmac, timingSafeEqual } from 'crypto'

// ── Client singleton ────────────────────────────────────────────────────────

declare global {
  // eslint-disable-next-line no-var
  var _redis: Redis | undefined
}

export function getRedis(): Redis | null {
  if (!process.env.REDIS_URL) return null

  if (!global._redis) {
    global._redis = new Redis(process.env.REDIS_URL, { lazyConnect: false })
    global._redis.on('error', (err) => console.error('[Redis]', err.message))
  }
  return global._redis
}

// ── Session data shape (mirrors session/redis.go) ──────────────────────────

export interface RedisSession {
  ja4?: string
  ja4_raw?: string
  http2?: string
  tls_json?: string
  client_ip?: string
  first_seen?: string
  last_seen?: string
  request_count?: string
  score?: string
  tls_changed?: string
}

export async function getSession(uuid: string): Promise<RedisSession | null> {
  const redis = getRedis()
  if (!redis) return null
  const data = await redis.hgetall(`session:${uuid}`)
  if (!data || Object.keys(data).length === 0) return null
  return data as RedisSession
}

// ── Cookie verification (mirrors session/session.go) ───────────────────────

export function verifySessionCookie(value: string, secret: string): string | null {
  const dotIdx = value.lastIndexOf('.')
  if (dotIdx < 0) return null

  const id = value.slice(0, dotIdx)
  const sig = value.slice(dotIdx + 1)
  if (sig.length !== 16) return null

  const expected = createHmac('sha256', secret).update(id).digest('hex').slice(0, 16)

  try {
    if (!timingSafeEqual(Buffer.from(sig, 'utf8'), Buffer.from(expected, 'utf8'))) return null
  } catch {
    return null
  }

  return id
}
