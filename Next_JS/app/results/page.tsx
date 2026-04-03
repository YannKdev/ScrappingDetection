'use client'

import { Suspense, useEffect, useRef, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import type { AnalysisResult, Signal } from '@/lib/types'
import type { FingerprintPayload } from '@/lib/types'
import { analyzeFingerprint } from '../actions'
import { computeMouseStats } from '@/lib/collect'
import { memStore } from '@/lib/mem-store'

// ── Helpers ───────────────────────────────────────────────────────────────────

function parseUA(ua: string): { browser: string; version: string; os: string; device: string } {
  const edgeM     = /Edg\/([\d]+)/.exec(ua)
  const samsungM  = /SamsungBrowser\/([\d]+)/.exec(ua)
  const chromeM   = /Chrome\/([\d]+)/.exec(ua)
  const ffM       = /Firefox\/([\d]+)/.exec(ua)
  const safariM   = /Version\/([\d]+).*Safari/.exec(ua)

  let browser = 'Unknown', version = ''
  if (edgeM)                              { browser = 'Edge';             version = edgeM[1] }
  else if (samsungM)                      { browser = 'Samsung Internet'; version = samsungM[1] }
  else if (chromeM && !/edg\//i.test(ua)) { browser = 'Chrome';           version = chromeM[1] }
  else if (ffM)                           { browser = 'Firefox';           version = ffM[1] }
  else if (safariM)                       { browser = 'Safari';            version = safariM[1] }

  let os = 'Unknown'
  if (/Windows NT/.test(ua))       os = 'Windows'
  else if (/Android/.test(ua))     os = 'Android'
  else if (/iPhone|iPad/.test(ua)) os = 'iOS'
  else if (/Mac OS X/.test(ua))    os = 'macOS'
  else if (/Linux/.test(ua))       os = 'Linux'

  let device = 'Desktop'
  if (/iPhone/.test(ua))                             device = 'Mobile'
  else if (/iPad/.test(ua))                          device = 'Tablet'
  else if (/Android/.test(ua) && !/Mobile/.test(ua)) device = 'Tablet'
  else if (/Android/.test(ua))                       device = 'Mobile'
  else if (/Mobile/.test(ua))                        device = 'Mobile'

  return { browser, version, os, device }
}

function detectH2Browser(fp: string): string {
  if (!fp) return ''
  const map: Record<number, number> = {}
  for (const pair of fp.split('|')[0].split(';')) {
    const [k, v] = pair.split(':').map(Number)
    if (!isNaN(k)) map[k] = v
  }
  if (map[4] === 6291456) return 'Chrome'
  if (map[4] === 131072)  return 'Firefox'
  if (map[4] === 65535)   return 'Safari'
  return ''
}

function uaMatchLabel(prediction: string, declaredUA: string): { label: string; color: string } {
  if (!prediction) return { label: '—', color: 'text-slate-500' }
  const app = prediction.toLowerCase()
  const ua  = declaredUA.toLowerCase()

  const appIsAmbiguous = /chromium/.test(app) && /firefox/.test(app)
  if (appIsAmbiguous) return { label: 'Ambiguous', color: 'text-slate-400' }

  const appIsScript  = /python|golang|curl|wget|java|node|ruby|postman|insomnia|scanner|biblioth/.test(app)
  const appIsChrome  = /\bchrome\b|\bchromium\b/.test(app) && !/safari/.test(app)
  const appIsFirefox = /\bfirefox\b/.test(app)
  const appIsSafari  = /\bsafari\b/.test(app) && !/chrome|chromium/.test(app)
  const uaIsBrowser  = /mozilla\/5\.0/.test(ua) && (/chrome\/|firefox\/|safari\/|edg\//.test(ua))
  const uaIsChromium = /chrome\/\d/.test(ua)
  const uaIsFirefox  = /firefox\/\d/.test(ua)
  const uaIsSafari   = /safari\/\d/.test(ua) && !uaIsChromium && !uaIsFirefox

  const mismatch =
    (appIsScript  && uaIsBrowser) ||
    (!appIsScript && (appIsChrome || appIsFirefox || appIsSafari) && !uaIsBrowser && declaredUA !== '') ||
    (appIsChrome  && uaIsBrowser  && !uaIsChromium) ||
    (appIsFirefox && uaIsBrowser  && !uaIsFirefox)  ||
    (appIsSafari  && uaIsBrowser  && !uaIsSafari)

  return mismatch
    ? { label: 'Inconsistent', color: 'text-red-400' }
    : { label: 'Consistent',   color: 'text-emerald-400' }
}

// ── Page shell ────────────────────────────────────────────────────────────────

export default function ResultsPage() {
  return (
    <Suspense fallback={<main className="flex min-h-screen items-center justify-center"><div className="h-8 w-8 animate-spin rounded-full border-2 border-indigo-400 border-t-transparent" /></main>}>
      <ResultsContent />
    </Suspense>
  )
}

function ResultsContent() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const [updating, setUpdating] = useState(false)
  const [storageUnavailable, setStorageUnavailable] = useState(false)

  const mousePositions = useRef<{ x: number; y: number }[]>([])
  const pageLoadTime = useRef(Date.now())

  useEffect(() => {
    let raw: string | null = null
    try { raw = sessionStorage.getItem('analysis') } catch { /* sessionStorage blocked */ }
    if (!raw) raw = memStore.getAnalysis()

    if (!raw) {
      if (searchParams.get('challenged') === '1') {
        setStorageUnavailable(true)
        return
      }
      router.replace('/')
      return
    }
    try { setResult(JSON.parse(raw)) } catch { router.replace('/'); return }

    pageLoadTime.current = Date.now()
    const onMove = (e: MouseEvent) => {
      mousePositions.current.push({ x: e.clientX, y: e.clientY })
    }
    window.addEventListener('mousemove', onMove, { passive: true })
    return () => window.removeEventListener('mousemove', onMove)
  }, [router])

  const handleUpdateBehavior = async (e: React.MouseEvent<HTMLButtonElement>) => {
    let rawPayload: string | null = null
    try { rawPayload = sessionStorage.getItem('fp_payload') } catch { /* blocked */ }
    if (!rawPayload) rawPayload = memStore.getFpPayload()
    if (!rawPayload) return
    setUpdating(true)
    try {
      const payload: FingerprintPayload = JSON.parse(rawPayload)
      payload.mouse = computeMouseStats(mousePositions.current)
      payload.timeToClickMs = Date.now() - pageLoadTime.current
      payload.untrustedClick = e.isTrusted ? 0 : 1
      const analysis = await analyzeFingerprint(payload)
      const analysisStr = JSON.stringify(analysis)
      memStore.setAnalysis(analysisStr)
      try { sessionStorage.setItem('analysis', analysisStr) } catch { /* blocked */ }
      setResult(analysis)
      mousePositions.current = []
      pageLoadTime.current = Date.now()
    } finally {
      setUpdating(false)
    }
  }

  if (storageUnavailable) {
    return (
      <main className="flex min-h-screen items-center justify-center px-4">
        <div className="max-w-sm rounded-xl border border-amber-500/30 bg-amber-500/10 p-8 text-center">
          <p className="mb-2 text-sm font-semibold text-amber-400">sessionStorage unavailable</p>
          <p className="text-xs leading-relaxed text-slate-400">
            JS analysis requires browser session storage.<br />
            Disable strict private browsing or use the{' '}
            <a href="/results_no_js" className="text-indigo-400 underline hover:text-indigo-300">no-JS mode</a>.
          </p>
        </div>
      </main>
    )
  }

  if (!result) {
    return (
      <main className="flex min-h-screen items-center justify-center">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-indigo-400 border-t-transparent" />
      </main>
    )
  }

  const {
    score, verdict, signals,
    ja4, http2Fingerprint, sessionId, clientIp, userAgent,
    ja4App, ja4AppL1, ja4AppL2, ja4AppL3,
  } = result

  const tlsSignals          = signals.filter(s => s.layer === 'tls')
  const tlsCoherenceSignals = signals.filter(s => s.layer === 'tls_coherence')
  const fingerprintSignals  = signals.filter(s => s.layer === 'fingerprint')
  const automationSignals   = signals.filter(s => s.layer === 'automation')
  const deviceSignals       = signals.filter(s => s.layer === 'device')
  const behaviorSignals     = signals.filter(s => s.layer === 'behavior')
  const headlessSignals     = signals.filter(s => s.layer === 'headless')

  const verdictConfig = {
    human:   { label: 'Valid',   bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', text: 'text-emerald-400', ring: '#10b981' },
    suspect: { label: 'Suspect', bg: 'bg-amber-500/10',   border: 'border-amber-500/30',   text: 'text-amber-400',   ring: '#f59e0b' },
    bot:     { label: 'Bot',     bg: 'bg-red-500/10',     border: 'border-red-500/30',      text: 'text-red-400',     ring: '#ef4444' },
  }[verdict]

  const parsedUA  = parseUA(userAgent)
  const h2Browser = detectH2Browser(http2Fingerprint)
  const { label: coherenceLabel, color: coherenceColor } = uaMatchLabel(ja4App, userAgent)

  return (
    <main className="mx-auto max-w-5xl px-4 py-12">

      {/* ── Header ───────────────────────────────────────────────────────── */}
      <div className="mb-8 flex items-center justify-between gap-3">
        <span className="text-xs text-slate-600">
          Session · <code className="font-mono text-slate-500">{sessionId.slice(0, 8)}…</code>
        </span>
        <button
          onClick={handleUpdateBehavior}
          disabled={updating}
          className="flex items-center gap-1.5 rounded-lg border border-indigo-500/30 bg-indigo-600/20 px-3 py-1.5 text-xs font-medium text-indigo-400 transition-colors hover:bg-indigo-600/30 hover:text-indigo-300 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {updating ? (
            <svg className="h-3 w-3 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
          ) : (
            <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          )}
          Update behavior
        </button>
      </div>

      {/* ── Verdict + Score ──────────────────────────────────────────────── */}
      <div className={`mb-6 rounded-2xl border ${verdictConfig.border} ${verdictConfig.bg} px-8 py-5`}>
        <div className="flex items-center gap-6 sm:justify-between">
          <div className="relative flex h-24 w-24 shrink-0 items-center justify-center">
            <svg className="absolute inset-0 -rotate-90" viewBox="0 0 144 144">
              <circle cx="72" cy="72" r="60" fill="none" stroke="#2a2d3a" strokeWidth="12" />
              <circle
                cx="72" cy="72" r="60"
                fill="none"
                stroke={verdictConfig.ring}
                strokeWidth="12"
                strokeDasharray={`${2 * Math.PI * 60}`}
                strokeDashoffset={`${2 * Math.PI * 60 * (
                  verdict === 'human'   ? 0.88 :
                  verdict === 'suspect' ? 0.50 : 0
                )}`}
                strokeLinecap="round"
                style={{ transition: 'stroke-dashoffset 0.8s ease' }}
              />
            </svg>
            <div className="z-10 text-center">
              <p className={`text-3xl font-bold ${verdictConfig.text}`}>{score}</p>
              <p className="text-[10px] text-slate-500">pts</p>
            </div>
          </div>
          <div>
            <p className="mb-0.5 text-[10px] font-semibold uppercase tracking-widest text-slate-500">Verdict</p>
            <p className={`text-4xl font-black uppercase ${verdictConfig.text}`}>{verdictConfig.label}</p>
            <p className="mt-1 text-xs text-slate-400">
              {verdict === 'human'   && 'No significant suspicious signals detected.'}
              {verdict === 'suspect' && 'Some ambiguous signals — monitoring recommended.'}
              {verdict === 'bot'     && 'Strong signals of automated behavior detected.'}
            </p>
          </div>
        </div>
      </div>

      {/* ── Declared config + Network fingerprint ────────────────────────── */}
      <div className="mb-6 grid gap-4 md:grid-cols-2">

        {/* Left: Declared config · UA */}
        <div className="rounded-xl border border-border bg-card p-5">
          <p className="mb-4 text-[10px] font-semibold uppercase tracking-widest text-slate-500">
            Declared config · UA
          </p>
          <div className="grid grid-cols-2 gap-x-4 gap-y-4">
            <div>
              <p className="mb-1 text-[10px] uppercase tracking-wider text-slate-600">Device</p>
              <p className="font-mono text-sm font-semibold text-white">{parsedUA.device}</p>
            </div>
            <div>
              <p className="mb-1 text-[10px] uppercase tracking-wider text-slate-600">System</p>
              <p className="font-mono text-sm font-semibold text-white">{parsedUA.os}</p>
            </div>
            <div>
              <p className="mb-1 text-[10px] uppercase tracking-wider text-slate-600">Browser</p>
              <p className="font-mono text-sm font-semibold text-white">{parsedUA.browser}</p>
            </div>
            <div>
              <p className="mb-1 text-[10px] uppercase tracking-wider text-slate-600">Version</p>
              <p className="font-mono text-sm font-semibold text-white">{parsedUA.version || '—'}</p>
            </div>
          </div>
          <div className="mt-4 border-t border-border pt-3">
            <p className="mb-1 text-[10px] uppercase tracking-wider text-slate-600">Raw User-Agent</p>
            <p className="break-all font-mono text-[10px] leading-relaxed text-slate-600">
              {userAgent || '(absent)'}
            </p>
          </div>
        </div>

        {/* Right: Network fingerprint */}
        <div className="rounded-xl border border-border bg-card p-5">
          <p className="mb-4 text-[10px] font-semibold uppercase tracking-widest text-slate-500">
            Network fingerprint
          </p>

          {/* TLS / JA4 */}
          <div className="mb-4">
            <div className="mb-2 flex items-center justify-between">
              <p className="text-[10px] uppercase tracking-wider text-slate-600">TLS / JA4</p>
              <span className={`font-mono text-xs ${coherenceColor}`}>
                {ja4App ? coherenceLabel : 'N/A'}
              </span>
            </div>
            <p className="mb-2 break-all font-mono text-xs font-semibold text-white">{ja4App || '—'}</p>

            {/* L1 / L2 / L3 avec tooltips */}
            <div className="space-y-1.5">
              <JA4Level
                level="L1"
                value={ja4AppL1}
                tip="Exact match in the JA4 database — identifies the application or TLS framework precisely (version, ciphers, extensions, order)."
              />
              <JA4Level
                level="L2"
                value={ja4AppL2}
                tip="Match on the cipher family (JA4 Part B). Identifies the TLS stack regardless of extension order."
              />
              <JA4Level
                level="L3"
                value={ja4AppL3}
                tip="Structural heuristic (Part A) — TLS protocol, max version, cipher/extension count. Classifies without a DB."
              />
            </div>

            <p className="mt-2 break-all font-mono text-[10px] leading-relaxed text-slate-600">
              {ja4 || '(absent)'}
            </p>
          </div>

          {/* HTTP/2 */}
          <div className="border-t border-border pt-3">
            <p className="mb-2 text-[10px] uppercase tracking-wider text-slate-600">HTTP/2 SETTINGS</p>
            <div className="flex items-center justify-between">
              <p className="font-mono text-sm font-semibold text-white">{h2Browser || '—'}</p>
              <span className={`text-[10px] ${http2Fingerprint ? 'text-emerald-600' : 'text-slate-600'}`}>
                {http2Fingerprint ? 'SETTINGS captured' : 'Absent / HTTP 1.1'}
              </span>
            </div>
            <p className="mt-1.5 break-all font-mono text-[10px] leading-relaxed text-slate-600">
              {http2Fingerprint || '—'}
            </p>
          </div>
        </div>

      </div>

      {/* ── Signal cards ─────────────────────────────────────────────────── */}
      <div className="mb-6 grid items-start gap-4 md:grid-cols-2">
        <SignalCard title="TLS / Network"  emoji="🔒" signals={tlsSignals} />
        <SignalCard title="UA Mismatch"    emoji="🌐" signals={tlsCoherenceSignals} />
        <SignalCard title="Automation"     emoji="🤖" signals={automationSignals} />
        <SignalCard title="Headless"       emoji="👻" signals={headlessSignals} />
        <SignalCard title="Behavior"       emoji="🖱️" signals={behaviorSignals} />
        <SignalCard title="Fingerprints"   emoji="🔍" signals={fingerprintSignals} />
        <SignalCard title="Device"         emoji="📱" signals={deviceSignals} />
      </div>

      {/* ── Technical details ────────────────────────────────────────────── */}
      <details className="group mb-8 rounded-xl border border-border bg-card">
        <summary className="flex cursor-pointer items-center justify-between px-6 py-4 text-[10px] font-semibold uppercase tracking-widest text-slate-600 hover:text-slate-400">
          Technical details
          <svg className="h-3.5 w-3.5 text-slate-700 transition-transform group-open:rotate-180"
            fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </summary>
        <div className="space-y-2 border-t border-border px-6 py-4 font-mono text-xs">
          <TechRow label="IP"        value={clientIp} />
          <TechRow label="Session"   value={sessionId} />
          <TechRow label="Timestamp" value={new Date(result.timestamp).toISOString()} />
        </div>
      </details>

      {/* ── No-JS test panel ─────────────────────────────────────────────── */}
      <div className="rounded-xl border border-slate-700/50 bg-slate-800/30 p-5">
        <div className="mb-3 flex items-center gap-2">
          <span className="rounded-md bg-slate-700 px-2 py-0.5 font-mono text-xs text-slate-300">GET</span>
          <p className="text-sm font-semibold text-slate-300">/results_no_js — no-interaction test</p>
        </div>
        <p className="mb-4 text-xs leading-relaxed text-slate-500">
          Analysis based solely on HTTP headers and TLS fingerprint.
          No JS signals available (canvas, audio, mouse, honeypot).
        </p>
        <div className="mb-4 space-y-1.5 font-mono text-xs text-slate-600">
          <div className="flex items-center gap-2"><span className="text-emerald-600">+</span> JA4 TLS fingerprint</div>
          <div className="flex items-center gap-2"><span className="text-emerald-600">+</span> User-Agent, Accept-Language, Accept-Encoding</div>
          <div className="flex items-center gap-2"><span className="text-emerald-600">+</span> Redis score (session history)</div>
          <div className="flex items-center gap-2"><span className="text-slate-700">-</span> Canvas, Audio, WebGL, mouse, honeypot</div>
        </div>
        <a
          href="/results_no_js"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center justify-center gap-2 rounded-lg border border-slate-600 bg-slate-700/50 px-4 py-2.5 text-sm font-medium text-slate-300 transition-colors hover:border-slate-500 hover:bg-slate-700 hover:text-white"
        >
          Open /results_no_js
          <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
          </svg>
        </a>
      </div>

    </main>
  )
}

// ── Sub-components ────────────────────────────────────────────────────────────

function Tooltip({ children, tip }: { children: React.ReactNode; tip: string }) {
  return (
    <div className="group/tip relative inline-flex shrink-0">
      {children}
      <div className="pointer-events-none invisible absolute bottom-full left-1/2 z-30 mb-2 w-60 -translate-x-1/2 rounded-xl border border-slate-700 bg-slate-900 p-3 shadow-2xl group-hover/tip:visible">
        <p className="whitespace-pre-line text-[10px] leading-relaxed text-slate-400">{tip}</p>
      </div>
    </div>
  )
}

function JA4Level({ level, value, tip }: { level: string; value: string; tip: string }) {
  const absent = !value || value === '—'
  return (
    <div className="flex items-start gap-2">
      <div className="flex items-center gap-1">
        <span className="w-5 font-mono text-[10px] font-semibold text-slate-500">{level}</span>
        <Tooltip tip={tip}>
          <span className="flex h-3.5 w-3.5 cursor-help items-center justify-center rounded-full bg-slate-800 text-[8px] leading-none text-slate-500 ring-1 ring-slate-700 hover:bg-slate-700 hover:text-slate-200">
            ?
          </span>
        </Tooltip>
      </div>
      <span className={`min-w-0 break-all font-mono text-[10px] leading-relaxed ${absent ? 'text-slate-700' : 'text-slate-400'}`}>
        {value || '—'}
      </span>
    </div>
  )
}

function SignalCard({ title, emoji, signals }: { title: string; emoji: string; signals: Signal[] }) {
  const [open, setOpen] = useState(true)
  const applicable = signals
    .filter(s => !s.notApplicable)
    .sort((a, b) => (b.suspicious ? 1 : 0) - (a.suspicious ? 1 : 0))
  const na         = signals.filter(s => s.notApplicable)
  const suspicious = applicable.filter(s => s.suspicious).length
  const total      = applicable.length

  return (
    <div className="rounded-xl border border-border bg-card">
      <button
        className="flex w-full cursor-pointer items-center justify-between px-5 py-3.5 text-left"
        onClick={() => setOpen(v => !v)}
      >
        <div className="flex items-center gap-2">
          <span className="text-sm leading-none">{emoji}</span>
          <h3 className="text-[11px] font-semibold uppercase tracking-widest text-white">{title}</h3>
        </div>
        <div className="flex items-center gap-2">
          <span className={`font-mono text-xs ${
            suspicious > 0 ? 'text-red-400' : total === 0 ? 'text-slate-700' : 'text-emerald-400'
          }`}>
            {suspicious}/{total}
          </span>
          <svg
            className={`h-3 w-3 text-slate-600 transition-transform ${open ? 'rotate-180' : ''}`}
            fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>

      {open && (
        <div className="border-t border-border px-4 py-3">
          <div className="space-y-0.5">
            {applicable.map(signal => (
              <SignalRow key={signal.id} signal={signal} />
            ))}
            {applicable.length === 0 && na.length === 0 && (
              <p className="px-2 text-xs text-slate-700">No signals</p>
            )}
          </div>

          {na.length > 0 && (
            <details className="group/na mt-3">
              <summary className="flex cursor-pointer list-none select-none items-center gap-1 text-[10px] text-slate-700 hover:text-slate-500">
                <svg className="h-2.5 w-2.5 transition-transform group-open/na:rotate-90" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                </svg>
                {na.length} not applicable
              </summary>
              <div className="mt-2 space-y-0.5 opacity-40">
                {na.map(signal => (
                  <SignalRow key={signal.id} signal={signal} />
                ))}
              </div>
            </details>
          )}
        </div>
      )}
    </div>
  )
}

function SignalRow({ signal }: { signal: Signal }) {
  const tooltipText = signal.suspicious && signal.weight > 0
    ? `${signal.explanation}\n\nScore: +${signal.weight} pts`
    : signal.explanation

  return (
    <div className="flex items-center justify-between gap-2 rounded-lg px-2 py-1.5">
      <span className="min-w-0 truncate text-xs text-slate-300">{signal.label}</span>
      <div className="flex shrink-0 items-center gap-1.5">
        <span className="max-w-[80px] truncate font-mono text-[11px] text-slate-500">{signal.value}</span>
        <span className={`h-2 w-2 shrink-0 rounded-full ${
          signal.notApplicable ? 'bg-slate-600'
            : signal.suspicious ? 'bg-red-400'
            : 'bg-emerald-400'
        }`} />
        <div className="group/tip relative shrink-0">
          <span className="flex h-3.5 w-3.5 cursor-help items-center justify-center rounded-full bg-slate-800 text-[8px] leading-none text-slate-500 ring-1 ring-slate-700 transition-colors hover:bg-slate-700 hover:text-slate-200">
            ?
          </span>
          <div className="pointer-events-none invisible absolute bottom-full right-0 z-30 mb-2 w-64 rounded-xl border border-slate-700 bg-slate-900 p-3 shadow-2xl group-hover/tip:visible">
            <p className="mb-1 text-[10px] font-semibold text-white">{signal.label}</p>
            <p className="whitespace-pre-line text-[10px] leading-relaxed text-slate-400">{tooltipText}</p>
          </div>
        </div>
      </div>
    </div>
  )
}

function TechRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-1 sm:flex-row sm:gap-4">
      <span className="w-28 shrink-0 text-slate-600">{label}</span>
      <span className="break-all text-slate-400">{value}</span>
    </div>
  )
}
