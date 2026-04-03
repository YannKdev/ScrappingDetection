// Route Handler — returns analysis result as JSON (no JS signals, headers + TLS only).
// Access via the Go proxy: https://localhost:8443/results_no_js
// GET /results_no_js → { score, verdict, signals, ja4, http2Fingerprint, sessionId, clientIp, timestamp }

import { NextResponse } from 'next/server'
import { headers } from 'next/headers'
import { getSession } from '@/lib/redis'
import { evaluateGet } from '@/lib/score'

export async function GET() {
  const headersList = await headers()

  // ── Headers injected by the Go proxy ──────────────────────────────────────
  const ja4            = headersList.get('x-ja4') ?? ''
  const http2          = headersList.get('x-http2-fingerprint') ?? ''
  const clientIp       = headersList.get('x-client-ip') ?? headersList.get('x-forwarded-for') ?? 'unknown'
  const proxySessionId = headersList.get('x-session-id') ?? ''
  const userAgent      = headersList.get('user-agent') ?? ''
  const acceptLanguage = headersList.get('accept-language') ?? ''
  const acceptEncoding = headersList.get('accept-encoding') ?? ''
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

  // ── Cookie fallback for session ID ─────────────────────────────────────────
  const secret = process.env.SESSION_SECRET ?? ''
  let cookieSessionId: string | null = null
  if (secret) {
    const cookieHeader = headersList.get('cookie') ?? ''
    const match = cookieHeader.match(/(?:^|;\s*)_fpsid=([^;]+)/)
    if (match) {
      const { verifySessionCookie } = await import('@/lib/redis')
      cookieSessionId = verifySessionCookie(match[1], secret)
    }
  }

  const sessionId = proxySessionId || cookieSessionId || 'no-session'

  // ── Redis session data ─────────────────────────────────────────────────────
  let tlsChanged = false
  let redisScore = 0
  if (sessionId !== 'no-session') {
    const session = await getSession(sessionId)
    if (session) {
      tlsChanged = session.tls_changed === 'true' || session.tls_changed === '1'
      redisScore = parseInt(session.score ?? '0', 10) || 0
    }
  }

  // ── Compute score ──────────────────────────────────────────────────────────
  const result = evaluateGet(
    { ja4, http2, tlsChanged, redisScore, userAgent, acceptLanguage, acceptEncoding, ja4App, ja4AppL1, ja4AppL2, ja4AppL3, ja4IsThreat, headerProfile, secChUaRaw, secChUaPlatform, secChUaMobile, tlsFingerprint },
    sessionId,
    clientIp,
  )

  return NextResponse.json(result)
}
