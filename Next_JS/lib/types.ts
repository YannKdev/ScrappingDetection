// ---------- POST /api/verify body ----------

export interface NavigatorInfo {
  webdriver: boolean
  platform: string
  language: string
  languages: string[]
  hardwareConcurrency: number
  deviceMemory: number | undefined
  pluginsCount: number
  cookieEnabled: boolean
  doNotTrack: string | null
  touchPoints: number
  windowChrome: boolean     // window.chrome present ?
  outerWidth: number        // 0 in headless without virtual display
  hasFocus: boolean         // false if tab never in foreground
  automationVars: string[]  // detected Selenium/Playwright/Puppeteer globals
  userAgent: string         // navigator.userAgent for cross-check with HTTP header
}

export interface ScreenInfo {
  width: number
  height: number
  availWidth: number
  availHeight: number
  colorDepth: number
  pixelRatio: number
}

export interface MouseStats {
  moveCount: number
  avgVelocity: number       // pixels/event
  maxVelocity: number
  straightLineRatio: number // 0–1: 1 = perfectly straight path (bot), -1 = not enough data
}

export interface HeadlessInfo {
  speechVoices: number          // -1 = API absent, 0 = headless (no voices), N = voice count
  mediaDeviceCount: number      // -1 = API absent/error, 0 = headless (no devices), N = device count
  patchedFunctions: string[]    // native functions replaced by CDP (non-[native code])
  stackTraceArtifacts: string[] // automation source URLs in stack traces (pptr://, __puppeteer..., etc.)
}

export interface FingerprintPayload {
  // From Web Worker (heavy)
  canvasHash: string
  audioHash: string
  // From main thread (light)
  webglVendor: string
  webglRenderer: string
  navigatorInfo: NavigatorInfo
  screenInfo: ScreenInfo
  timezone: string
  mouse: MouseStats
  timeToClickMs: number     // time from page load to button click
  honeypot: string          // must always be empty for real users
  untrustedClick: number    // -1=no click observed, 0=all clicks trusted, 1=isTrusted=false detected
  headless: HeadlessInfo
}

// ---------- Signal evaluation ----------

export type Layer = 'tls' | 'fingerprint' | 'automation' | 'device' | 'behavior' | 'headless' | 'tls_coherence'

export interface Signal {
  id: string
  label: string
  layer: Layer
  value: string
  suspicious: boolean
  weight: number            // contribution to score if suspicious
  explanation: string
  notApplicable?: boolean   // true when signal couldn't be measured (show grey dot)
}

// ---------- POST /api/verify response ----------

export interface AnalysisResult {
  sessionId: string
  score: number             // 0–100
  verdict: 'human' | 'suspect' | 'bot'
  signals: Signal[]
  // Raw TLS data (injected by Go proxy as headers)
  ja4: string
  http2Fingerprint: string
  clientIp: string
  timestamp: number
  userAgent: string         // User-Agent header / navigator.userAgent
  ja4App: string            // Best available prediction (L1 > L2 > L3)
  ja4AppL1: string          // Level 1: exact JA4 DB entry (full hash match)
  ja4AppL2: string          // Level 2: Part-B cipher-suite family (stable across versions)
  ja4AppL3: string          // Level 3: Part-A structural heuristic (fallback)
}
