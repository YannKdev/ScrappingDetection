import { NextRequest, NextResponse } from 'next/server'
import { cookies, headers } from 'next/headers'
import { getSession, verifySessionCookie } from '@/lib/redis'
import { evaluateGet } from '@/lib/score'

// ── GET /api/verify ──────────────────────────────────────────────────────────
// Lightweight analysis based solely on HTTP headers + TLS + Redis.
// Usable with curl, python, etc. for monitoring or testing.
// Available signals: JA4, User-Agent, Accept-Language, Accept-Encoding, Redis session.
export async function GET(req: NextRequest) {
  const headersList    = await headers()
  const ja4            = headersList.get('x-ja4') ?? ''
  const http2          = headersList.get('x-http2-fingerprint') ?? ''
  const clientIp       = headersList.get('x-client-ip') ?? req.headers.get('x-forwarded-for') ?? 'unknown'
  const proxySessionId = headersList.get('x-session-id') ?? ''
  const userAgent      = headersList.get('user-agent') ?? ''
  const acceptLanguage = headersList.get('accept-language') ?? ''
  const acceptEncoding = headersList.get('accept-encoding') ?? ''

  const secret = process.env.SESSION_SECRET ?? ''
  const cookieStore    = await cookies()
  const cookieValue    = cookieStore.get('_fpsid')?.value ?? ''
  const cookieSessionId = secret ? verifySessionCookie(cookieValue, secret) : null
  const sessionId      = proxySessionId || cookieSessionId || 'no-session'

  let tlsChanged = false
  let redisScore = 0
  if (sessionId !== 'no-session') {
    const session = await getSession(sessionId)
    if (session) {
      tlsChanged = session.tls_changed === 'true' || session.tls_changed === '1'
      redisScore = parseInt(session.score ?? '0', 10) || 0
    }
  }

  const ja4App          = headersList.get('x-ja4-app') ?? ''
  const ja4AppL1        = headersList.get('x-ja4-app-l1') ?? ''
  const ja4AppL2        = headersList.get('x-ja4-app-l2') ?? ''
  const ja4AppL3        = headersList.get('x-ja4-app-l3') ?? ''
  const ja4IsThreat     = headersList.get('x-ja4-is-threat') === 'true'
  const headerProfile   = headersList.get('x-header-profile') ?? ''
  const secChUaRaw      = headersList.get('x-sec-ch-ua-raw') ?? ''
  const secChUaPlatform = headersList.get('x-sec-ch-ua-platform') ?? ''
  const secChUaMobile   = headersList.get('x-sec-ch-ua-mobile') ?? ''
  const tlsFingerprint  = headersList.get('x-tls-fingerprint') ?? ''

  const result = evaluateGet(
    { ja4, http2, tlsChanged, redisScore, userAgent, acceptLanguage, acceptEncoding, ja4App, ja4AppL1, ja4AppL2, ja4AppL3, ja4IsThreat, headerProfile, secChUaRaw, secChUaPlatform, secChUaMobile, tlsFingerprint },
    sessionId,
    clientIp,
  )

  return NextResponse.json(result)
}
