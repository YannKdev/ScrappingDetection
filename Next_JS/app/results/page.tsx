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

function uaMatchLabel(prediction: string, declaredUA: string): { label: string; cls: string } {
  if (!prediction) return { label: '—', cls: 'text-muted' }
  const app = prediction.toLowerCase()
  const ua  = declaredUA.toLowerCase()

  const appIsAmbiguous = /chromium/.test(app) && /firefox/.test(app)
  if (appIsAmbiguous) return { label: 'Ambiguous', cls: 'text-secondary' }

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
    ? { label: 'Inconsistent', cls: 'text-danger' }
    : { label: 'Consistent',   cls: 'text-success' }
}

// ── Page shell ────────────────────────────────────────────────────────────────

export default function ResultsPage() {
  return (
    <Suspense fallback={
      <main className="chargement" style={{ minHeight: '100vh', alignItems: 'center' }}>
        <div className="spinner-border text-primary" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
      </main>
    }>
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
      <main className="container py-5">
        <div className="row justify-content-center">
          <div className="col-sm-8 col-md-5">
            <div className="card">
              <div className="card-body text-center py-4">
                <p className="fw-semibold text-warning mb-2">sessionStorage unavailable</p>
                <p className="text-muted small mb-0">
                  JS analysis requires browser session storage.<br />
                  Disable strict private browsing or use the{' '}
                  <a href="/results_no_js">no-JS mode</a>.
                </p>
              </div>
            </div>
          </div>
        </div>
      </main>
    )
  }

  if (!result) {
    return (
      <main className="chargement" style={{ minHeight: '100vh', alignItems: 'center' }}>
        <div className="spinner-border text-primary" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
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
    human:   { label: 'Valid',   badgeCls: 'bg-success', borderCls: 'border-success', textCls: 'text-success',
                desc: 'No significant suspicious signals detected.' },
    suspect: { label: 'Suspect', badgeCls: 'bg-warning', borderCls: 'border-warning', textCls: 'text-warning',
                desc: 'Some ambiguous signals — monitoring recommended.' },
    bot:     { label: 'Bot',     badgeCls: 'bg-danger',  borderCls: 'border-danger',  textCls: 'text-danger',
                desc: 'Strong signals of automated behavior detected.' },
  }[verdict]

  const parsedUA  = parseUA(userAgent)
  const h2Browser = detectH2Browser(http2Fingerprint)
  const { label: coherenceLabel, cls: coherenceCls } = uaMatchLabel(ja4App, userAgent)

  return (
    <main className="container py-5">

      {/* ── Navbar ────────────────────────────────────────────────────────── */}
      <nav className="navbar navbar-dark bg-dark px-3 mb-4 rounded">
        <span className="navbar-brand mb-0 h6">Bot Detection Engine</span>
        <div className="d-flex align-items-center gap-3">
          <span className="text-muted small font-monospace">
            Session: {sessionId.slice(0, 8)}…
          </span>
          <button
            onClick={handleUpdateBehavior}
            disabled={updating}
            className="btn btn-sm btn-outline-primary"
          >
            {updating
              ? <><span className="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true" /> Updating…</>
              : '↺ Update behavior'
            }
          </button>
        </div>
      </nav>

      {/* ── Verdict + Score ──────────────────────────────────────────────── */}
      <div className={`card mb-4 border-2 ${verdictConfig.borderCls}`}>
        <div className="card-body">
          <div className="d-flex align-items-center gap-4">
            <div className="text-center" style={{ minWidth: '5rem' }}>
              <div className={`fs-3 fw-bold ${verdictConfig.textCls}`}>{score}</div>
              <div className="text-muted small">pts</div>
            </div>
            <div>
              <div className="text-muted small text-uppercase fw-semibold mb-1">Verdict</div>
              <span className={`badge ${verdictConfig.badgeCls} fs-6 fw-bold text-uppercase mb-1`}>
                {verdictConfig.label}
              </span>
              <div className="text-muted small">{verdictConfig.desc}</div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Declared config + Network fingerprint ────────────────────────── */}
      <div className="row row-cols-1 row-cols-md-2 g-4 mb-4">

        {/* Declared config */}
        <div className="col">
          <div className="card h-100">
            <div className="card-header fw-semibold">Declared config · UA</div>
            <div className="card-body">
              <div className="row row-cols-2 g-3 mb-3">
                <div className="col">
                  <div className="text-muted small text-uppercase mb-1">Device</div>
                  <code>{parsedUA.device}</code>
                </div>
                <div className="col">
                  <div className="text-muted small text-uppercase mb-1">System</div>
                  <code>{parsedUA.os}</code>
                </div>
                <div className="col">
                  <div className="text-muted small text-uppercase mb-1">Browser</div>
                  <code>{parsedUA.browser}</code>
                </div>
                <div className="col">
                  <div className="text-muted small text-uppercase mb-1">Version</div>
                  <code>{parsedUA.version || '—'}</code>
                </div>
              </div>
              <hr className="my-2" />
              <div className="text-muted small text-uppercase mb-1">Raw User-Agent</div>
              <code className="small text-break d-block text-muted">
                {userAgent || '(absent)'}
              </code>
            </div>
          </div>
        </div>

        {/* Network fingerprint */}
        <div className="col">
          <div className="card h-100">
            <div className="card-header fw-semibold">Network fingerprint</div>
            <div className="card-body">

              {/* TLS / JA4 */}
              <div className="mb-3">
                <div className="d-flex justify-content-between align-items-center mb-1">
                  <span className="text-muted small text-uppercase">TLS / JA4</span>
                  <span className={`small font-monospace ${coherenceCls}`}>
                    {ja4App ? coherenceLabel : 'N/A'}
                  </span>
                </div>
                <code className="small text-break d-block mb-2">{ja4App || '—'}</code>

                <table className="table table-sm mb-2">
                  <tbody>
                    <tr>
                      <th scope="row" className="text-muted small" style={{ width: '2.5rem' }}>L1</th>
                      <td>
                        <code className="small text-break">{ja4AppL1 || '—'}</code>
                        <div className="text-muted" style={{ fontSize: '0.75rem' }}>
                          Exact match in the JA4 database — identifies the application or TLS framework precisely.
                        </div>
                      </td>
                    </tr>
                    <tr>
                      <th scope="row" className="text-muted small">L2</th>
                      <td>
                        <code className="small text-break">{ja4AppL2 || '—'}</code>
                        <div className="text-muted" style={{ fontSize: '0.75rem' }}>
                          Match on the cipher family (JA4 Part B). Identifies the TLS stack regardless of extension order.
                        </div>
                      </td>
                    </tr>
                    <tr>
                      <th scope="row" className="text-muted small">L3</th>
                      <td>
                        <code className="small text-break">{ja4AppL3 || '—'}</code>
                        <div className="text-muted" style={{ fontSize: '0.75rem' }}>
                          Structural heuristic (Part A) — TLS protocol, max version, cipher/extension count.
                        </div>
                      </td>
                    </tr>
                  </tbody>
                </table>

                <code className="small text-break text-muted d-block">{ja4 || '(absent)'}</code>
              </div>

              {/* HTTP/2 */}
              <hr className="my-2" />
              <div className="text-muted small text-uppercase mb-1">HTTP/2 SETTINGS</div>
              <div className="d-flex justify-content-between align-items-center">
                <code>{h2Browser || '—'}</code>
                <span className={`small ${http2Fingerprint ? 'text-success' : 'text-muted'}`}>
                  {http2Fingerprint ? 'SETTINGS captured' : 'Absent / HTTP 1.1'}
                </span>
              </div>
              <code className="small text-break text-muted d-block mt-1">
                {http2Fingerprint || '—'}
              </code>
            </div>
          </div>
        </div>

      </div>

      {/* ── Signal cards ─────────────────────────────────────────────────── */}
      <div className="row row-cols-1 row-cols-md-2 g-4 mb-4">
        <div className="col"><SignalCard title="TLS / Network" signals={tlsSignals} /></div>
        <div className="col"><SignalCard title="UA Mismatch"   signals={tlsCoherenceSignals} /></div>
        <div className="col"><SignalCard title="Automation"    signals={automationSignals} /></div>
        <div className="col"><SignalCard title="Headless"      signals={headlessSignals} /></div>
        <div className="col"><SignalCard title="Behavior"      signals={behaviorSignals} /></div>
        <div className="col"><SignalCard title="Fingerprints"  signals={fingerprintSignals} /></div>
        <div className="col"><SignalCard title="Device"        signals={deviceSignals} /></div>
      </div>

      {/* ── Technical details ────────────────────────────────────────────── */}
      <details className="mb-4">
        <summary className="card-header fw-semibold" style={{ listStyle: 'none', cursor: 'pointer' }}>
          <div className="card">
            <div className="card-header fw-semibold d-flex justify-content-between align-items-center">
              Technical details
              <span className="text-muted small">▾</span>
            </div>
          </div>
        </summary>
        <div className="card border-top-0" style={{ borderTopLeftRadius: 0, borderTopRightRadius: 0 }}>
          <div className="card-body font-monospace small">
            <TechRow label="IP"        value={clientIp} />
            <TechRow label="Session"   value={sessionId} />
            <TechRow label="Timestamp" value={new Date(result.timestamp).toISOString()} />
          </div>
        </div>
      </details>

      {/* ── No-JS test panel ─────────────────────────────────────────────── */}
      <div className="card">
        <div className="card-body">
          <div className="mb-2">
            <span className="badge bg-secondary me-2">GET</span>
            <span className="fw-semibold">/results_no_js — no-interaction test</span>
          </div>
          <p className="text-muted small mb-3">
            Analysis based solely on HTTP headers and TLS fingerprint.
            No JS signals available (canvas, audio, mouse, honeypot).
          </p>
          <ul className="list-unstyled font-monospace small text-muted mb-3">
            <li><span className="text-success me-2">+</span> JA4 TLS fingerprint</li>
            <li><span className="text-success me-2">+</span> User-Agent, Accept-Language, Accept-Encoding</li>
            <li><span className="text-success me-2">+</span> Redis score (session history)</li>
            <li><span className="text-secondary me-2">−</span> Canvas, Audio, WebGL, mouse, honeypot</li>
          </ul>
          <a
            href="/results_no_js"
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-outline-secondary btn-sm"
          >
            Open /results_no_js ↗
          </a>
        </div>
      </div>

    </main>
  )
}

// ── Sub-components ────────────────────────────────────────────────────────────

function SignalCard({ title, signals }: { title: string; signals: Signal[] }) {
  const [open, setOpen] = useState(true)
  const applicable = signals
    .filter(s => !s.notApplicable)
    .sort((a, b) => (b.suspicious ? 1 : 0) - (a.suspicious ? 1 : 0))
  const na         = signals.filter(s => s.notApplicable)
  const suspicious = applicable.filter(s => s.suspicious).length
  const total      = applicable.length

  const countCls = suspicious > 0 ? 'text-danger' : total === 0 ? 'text-muted' : 'text-success'

  return (
    <div className="card h-100">
      <div
        className="card-header d-flex justify-content-between align-items-center"
        style={{ cursor: 'pointer' }}
        onClick={() => setOpen(v => !v)}
      >
        <span className="fw-semibold">{title}</span>
        <span className={`font-monospace small ${countCls}`}>
          {suspicious}/{total}
        </span>
      </div>

      {open && (
        <div className="card-body p-0">
          <table className="table table-hover table-striped mb-0 w-100">
            <tbody>
              {applicable.map(signal => (
                <SignalRow key={signal.id} signal={signal} />
              ))}
              {applicable.length === 0 && na.length === 0 && (
                <tr>
                  <td colSpan={3} className="text-muted small px-3 py-2">No signals</td>
                </tr>
              )}
            </tbody>
          </table>

          {na.length > 0 && (
            <details className="px-3 py-2">
              <summary className="text-muted small" style={{ cursor: 'pointer' }}>
                {na.length} not applicable
              </summary>
              <table className="table table-sm mb-0 mt-2 opacity-50">
                <tbody>
                  {na.map(signal => (
                    <SignalRow key={signal.id} signal={signal} />
                  ))}
                </tbody>
              </table>
            </details>
          )}
        </div>
      )}
    </div>
  )
}

function SignalRow({ signal }: { signal: Signal }) {
  const tooltipText = signal.suspicious && signal.weight > 0
    ? `${signal.explanation} — Score: +${signal.weight} pts`
    : signal.explanation

  const dotCls = signal.notApplicable
    ? 'bg-secondary'
    : signal.suspicious ? 'bg-danger' : 'bg-success'

  return (
    <tr title={tooltipText}>
      <td className="px-3 py-2 small">{signal.label}</td>
      <td className="px-2 py-2 font-monospace small text-muted text-truncate" style={{ maxWidth: '8rem' }}>
        {signal.value}
      </td>
      <td className="px-3 py-2 text-end" style={{ width: '2rem' }}>
        <span
          className={`badge rounded-pill ${dotCls}`}
          style={{ width: '0.6rem', height: '0.6rem', padding: 0, display: 'inline-block' }}
        />
      </td>
    </tr>
  )
}

function TechRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="d-flex gap-3 mb-2">
      <span className="text-muted" style={{ minWidth: '6rem' }}>{label}</span>
      <span className="text-break">{value}</span>
    </div>
  )
}
