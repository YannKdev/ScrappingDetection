import { NextRequest, NextResponse } from 'next/server'

// Routes excluded from verification (the verify API must remain accessible)
const EXCLUDED = ['/api/verify', '/_next', '/favicon.ico']

export function proxy(req: NextRequest) {
  const { pathname } = req.nextUrl

  if (EXCLUDED.some(p => pathname.startsWith(p))) {
    return NextResponse.next()
  }

  // ── JA4 captured by the Go proxy ──────────────────────────────────────────
  const ja4       = req.headers.get('x-ja4') ?? ''
  const sessionId = req.headers.get('x-session-id') ?? ''

  // JA4 absent = direct access without going through the Go proxy
  // → let through (local dev or monitoring)
  if (!ja4) {
    return NextResponse.next()
  }

  // ── Redis score carried by X-Session-ID header ────────────────────────────
  // The Go proxy has already computed and stored the score in Redis.
  // For a synchronous check in the middleware (without a Redis call),
  // we rely solely on signals present in the headers.

  // Read score from an optional header the proxy could inject
  // (not yet implemented on the Go side — see note below)
  const proxyScore = parseInt(req.headers.get('x-bot-score') ?? '0', 10)

  if (proxyScore >= 60) {
    // Bot score too high → block or redirect to challenge
    return new NextResponse('Access denied', { status: 403 })
  }

  // Continue normally — JA4 is available for pages if needed
  const res = NextResponse.next()
  // Expose JA4 to Server Components via an internal response header
  res.headers.set('x-ja4-passthrough', ja4)
  res.headers.set('x-session-passthrough', sessionId)
  return res
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
}
