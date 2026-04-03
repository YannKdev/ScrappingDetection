'use server'
// Server Action — replaces the POST /api/verify endpoint.
// Called from page.tsx like a regular async function.
// Next.js routes it via /_next/action with an opaque ID — no public REST endpoint.

import { headers, cookies } from 'next/headers'
import { getSession, verifySessionCookie } from '@/lib/redis'
import { evaluate } from '@/lib/score'
import type { FingerprintPayload, AnalysisResult } from '@/lib/types'

export async function analyzeFingerprint(payload: FingerprintPayload): Promise<AnalysisResult> {
  const headersList = await headers()

  // ── Headers injected by the Go proxy ─────────────────────────────────────
  const ja4            = headersList.get('x-ja4') ?? ''
  const http2          = headersList.get('x-http2-fingerprint') ?? ''
  const clientIp       = headersList.get('x-client-ip') ?? headersList.get('x-forwarded-for') ?? 'unknown'
  const proxySessionId = headersList.get('x-session-id') ?? ''

  // ── Session ID via cookie _fpsid ───────────────────────────────────────────
  const secret      = process.env.SESSION_SECRET ?? ''
  const cookieStore = await cookies()
  const cookieValue = cookieStore.get('_fpsid')?.value ?? ''
  const cookieSessionId = secret ? verifySessionCookie(cookieValue, secret) : null
  const sessionId   = proxySessionId || cookieSessionId || 'no-session'

  // ── Redis: TLS change + cumulative score ─────────────────────────────────
  let tlsChanged = false
  let redisScore = 0
  if (sessionId !== 'no-session') {
    const session = await getSession(sessionId)
    if (session) {
      tlsChanged = session.tls_changed === 'true' || session.tls_changed === '1'
      redisScore = parseInt(session.score ?? '0', 10) || 0
    }
  }

  const httpUserAgent    = headersList.get('user-agent') ?? ''
  const ja4App           = headersList.get('x-ja4-app') ?? ''
  const ja4AppL1         = headersList.get('x-ja4-app-l1') ?? ''
  const ja4AppL2         = headersList.get('x-ja4-app-l2') ?? ''
  const ja4AppL3         = headersList.get('x-ja4-app-l3') ?? ''
  const ja4IsThreat      = headersList.get('x-ja4-is-threat') === 'true'
  const headerProfile    = headersList.get('x-header-profile') ?? ''
  const secChUaRaw       = headersList.get('x-sec-ch-ua-raw') ?? ''
  const secChUaPlatform  = headersList.get('x-sec-ch-ua-platform') ?? ''
  const secChUaMobile    = headersList.get('x-sec-ch-ua-mobile') ?? ''
  const tlsFingerprint   = headersList.get('x-tls-fingerprint') ?? ''

  return evaluate(
    payload,
    { ja4, http2, tlsChanged, redisScore, httpUserAgent, ja4App, ja4AppL1, ja4AppL2, ja4AppL3, ja4IsThreat, headerProfile, secChUaRaw, secChUaPlatform, secChUaMobile, tlsFingerprint },
    sessionId,
    clientIp,
  )
}
