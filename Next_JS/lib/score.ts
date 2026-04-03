// Server-side scoring logic.
// Combines JS signals (from POST body) with TLS signals (from Go proxy headers / Redis).
// evaluateGet() handles GET requests where only HTTP headers are available (no JS payload).

import type { FingerprintPayload, Signal, AnalysisResult } from './types'

// ── Helpers ───────────────────────────────────────────────────────────────────

const VIRTUAL_RENDERERS = ['swiftshader', 'llvmpipe', 'mesa', 'softpipe', 'vmware', 'virtualbox', 'd3d9']

function isVirtualRenderer(renderer: string): boolean {
  const r = renderer.toLowerCase()
  return VIRTUAL_RENDERERS.some(v => r.includes(v))
}

function uaOS(ua: string): 'windows' | 'mac' | 'linux' | 'android' | 'ios' | 'unknown' {
  const u = ua.toLowerCase()
  if (u.includes('windows'))                          return 'windows'
  if (u.includes('macintosh') || u.includes('mac os')) return 'mac'
  if (u.includes('android'))                          return 'android'
  if (u.includes('iphone') || u.includes('ipad'))    return 'ios'
  if (u.includes('linux'))                            return 'linux'
  return 'unknown'
}

function platformOS(platform: string): 'windows' | 'mac' | 'linux' | 'unknown' {
  const p = platform.toLowerCase()
  if (p.startsWith('win'))                                       return 'windows'
  if (p.startsWith('mac'))                                       return 'mac'
  if (p.includes('linux') || p.includes('arm') || p.includes('pike')) return 'linux'
  return 'unknown'
}

// Returns true if the User-Agent string looks like a real browser.
function isLikelyBrowserUA(ua: string): boolean {
  const u = ua.toLowerCase()
  return u.includes('mozilla/5.0') && (
    u.includes('chrome/') || u.includes('firefox/') ||
    u.includes('safari/')  || u.includes('edg/')
  )
}

// ── HTTP header presence fingerprint ─────────────────────────────────────────
// Compares the browser-hint headers actually present (from X-Header-Profile)
// against what the declared User-Agent should send.
// Returns a penalty 0-30 and a human-readable detail string.

interface HeaderPenalty { penalty: number; details: string }

function computeHeaderProfilePenalty(
  profileHeader: string,
  ua: string,
  secChUaRaw: string,
  secChUaPlatform: string,
  secChUaMobile: string,
): HeaderPenalty {
  const profile = profileHeader.split(',').filter(Boolean)
  const u = ua.toLowerCase()

  const isChrome  = /chrome\/\d/.test(u) && !/edg\//.test(u) && !/opr\//.test(u) && !/chromium/.test(u)
  const isEdge    = /edg\/\d/.test(u)
  const isFirefox = /firefox\/\d/.test(u)
  const isSafari  = /safari\/\d/.test(u) && !isChrome && !isEdge && !/firefox/.test(u)
  const isChromium = isChrome || isEdge
  const isBrowser  = isChromium || isFirefox || isSafari

  const hasSecChUa       = profile.includes('sec-ch-ua')
  const hasSecChUaMobile = profile.includes('sec-ch-ua-mobile')
  const hasSecChUaPlatf  = profile.includes('sec-ch-ua-platform')
  const hasUIR           = profile.includes('upgrade-insecure-requests')
  const secFetch         = ['sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest']
  const missedFetch      = secFetch.filter(h => !profile.includes(h))

  let penalty = 0
  const issues: string[] = []

  if (isChromium) {
    // ── sec-ch-ua presence ──────────────────────────────────────────────────
    if (!hasSecChUa) {
      penalty += 20
      issues.push('sec-ch-ua absent (Chromium always sends it)')
    } else {
      // Version consistency: Chrome/131 → Sec-Ch-Ua should contain v="131"
      if (secChUaRaw) {
        const uaVersion = (u.match(/(?:chrome|edg)\/(\d+)/) ?? [])[1]
        if (uaVersion && !secChUaRaw.includes(`v="${uaVersion}"`)) {
          penalty += 15
          issues.push(`sec-ch-ua version ≠ UA (UA:${uaVersion})`)
        }
      }

      // ── Trio completeness ──────────────────────────────────────────────────
      // Chromium sends all 3 sec-ch-ua-* headers together, always.
      if (!hasSecChUaMobile || !hasSecChUaPlatf) {
        penalty += 10
        issues.push('sec-ch-ua-mobile/platform missing (incomplete CH trio)')
      } else {
        // ── sec-ch-ua-platform vs OS in User-Agent ─────────────────────────
        // e.g. Chrome with UA "Windows NT" should have platform="Windows",
        //      not "Linux" or "macOS".
        if (secChUaPlatform) {
          const platLower = secChUaPlatform.replace(/"/g, '').toLowerCase()
          const os = uaOS(ua)
          const coherent =
            (os === 'windows' && platLower.includes('windows')) ||
            (os === 'mac'     && platLower.includes('mac'))     ||
            (os === 'linux'   && (platLower.includes('linux') || platLower.includes('chrome'))) ||
            (os === 'android' && platLower.includes('android')) ||
            os === 'ios' || os === 'unknown'
          if (!coherent) {
            penalty += 15
            issues.push(`sec-ch-ua-platform="${platLower}" ≠ OS UA (${os})`)
          }
        }

        // ── sec-ch-ua-mobile vs device type in User-Agent ─────────────────
        // ?0 = desktop, ?1 = mobile/tablet
        if (secChUaMobile) {
          const isMobileUA  = /android|mobile|iphone|ipad/.test(u)
          const chMobileOn  = secChUaMobile.trim() === '?1'
          if (chMobileOn !== isMobileUA) {
            penalty += 10
            issues.push(`sec-ch-ua-mobile=${secChUaMobile} ≠ UA (${isMobileUA ? 'mobile' : 'desktop'})`)
          }
        }
      }
    }

    if (missedFetch.length > 0) {
      penalty += missedFetch.length * 5
      issues.push(`sec-fetch missing: ${missedFetch.join(', ')}`)
    }

  } else if (isFirefox) {
    // Firefox never sends sec-ch-ua (no Client Hints support on navigation)
    if (hasSecChUa) {
      penalty += 15
      issues.push('sec-ch-ua present (Firefox never sends it)')
    }
    if (missedFetch.length > 0) {
      penalty += missedFetch.length * 5
      issues.push(`sec-fetch missing: ${missedFetch.join(', ')}`)
    }

  } else if (isSafari) {
    // Safari does not implement Client Hints
    if (hasSecChUa) {
      penalty += 20
      issues.push('sec-ch-ua present (Safari does not send it)')
    }

  } else if (!isBrowser && ua !== '') {
    if (hasSecChUa || missedFetch.length < 3) {
      // Non-browser UA carrying browser-only headers → bot trying to blend in
      penalty += 10
      issues.push('Browser headers on non-browser UA')
    } else {
      // Non-browser UA with zero browser metadata → bare API/script client
      penalty += 10
      issues.push('No browser headers (tool/script request)')
    }
  }

  // ── upgrade-insecure-requests ─────────────────────────────────────────────
  // UIR is sent on HTML navigations (Sec-Fetch-Mode: navigate) but NOT on
  // fetch()/XHR requests (e.g. Server Actions, API calls), where Sec-Fetch-Mode
  // is "cors" or "same-origin". Penalise only when all Sec-Fetch headers are
  // also absent — that combination is a genuine bot signal (bare HTTP client
  // with no browser-level metadata at all).
  if (isBrowser && !hasUIR && missedFetch.length === secFetch.length) {
    penalty += 5
    issues.push('upgrade-insecure-requests absent (browsers send it on navigation)')
  }

  return {
    penalty: Math.min(penalty, 30),
    details: issues.length > 0 ? issues.join(' · ') : 'Consistent',
  }
}

// ── JA4 Part A parser ─────────────────────────────────────────────────────────
// JA4 format: {transport}{version}{sni}{ciphers:02d}{exts:02d}{alpn}_{B}_{C}
// Example:     t           13       d    15           16         h2
interface JA4PartA {
  version: string    // "13"=TLS1.3, "12"=TLS1.2
  sni:     'i' | 'd' // 'i'=IP (no SNI), 'd'=domain
  ciphers: number
  exts:    number
  alpn:    string    // "h2", "h1", "00"=none
}

function parseJA4PartA(ja4: string): JA4PartA | null {
  const m = ja4.match(/^[tq](\d{2})([di])(\d{2})(\d{2})(.{2})_/)
  if (!m) return null
  return {
    version: m[1],
    sni:     m[2] as 'i' | 'd',
    ciphers: parseInt(m[3]),
    exts:    parseInt(m[4]),
    alpn:    m[5],
  }
}

// JA4 Part A theoretical consistency rules:
// - version "12" (TLS 1.2 max) + browser UA → suspicious (browsers enforce TLS 1.3)
// - alpn "00" (no ALPN)        → suspicious (any modern HTTP client should negotiate h2/http1.1)
// - ciphers ≤ 4                → suspicious universally (degenerate TLS stack)
// - ciphers 5-9 + browser UA   → suspicious (browsers have 15-20, only fires when JA4 not in DB)
// - exts   < 6  + browser UA   → suspicious (browsers have 8-16,  only fires when JA4 not in DB)
function ja4Anomalies(ja4: string, ua: string): {
  lowVersion: boolean; noAlpn: boolean; fewCiphers: boolean
  suspiciousCiphers: boolean; fewExts: boolean
} {
  const p = parseJA4PartA(ja4)
  if (!p) return { lowVersion: false, noAlpn: false, fewCiphers: false, suspiciousCiphers: false, fewExts: false }
  const uaIsBrowser = isLikelyBrowserUA(ua)
  return {
    lowVersion:        p.version === '12' && uaIsBrowser,
    noAlpn:            p.alpn    === '00',
    fewCiphers:        p.ciphers <= 4,
    suspiciousCiphers: p.ciphers >= 5 && p.ciphers < 10 && uaIsBrowser, // browsers have 15-20
    fewExts:           p.exts    <  6  && uaIsBrowser,                   // browsers have 8-16
  }
}

// JA4 DB App cross-check (3 cases):
// 1. JA4 DB → script/tool, UA → browser       : bot masking as browser
// 2. JA4 DB → browser,       UA → non-browser  : browser fingerprint replayed by script
// 3. JA4 DB → specific browser (Chrome/Firefox/Safari), UA → different browser : identity spoofing
function ja4AppVsUA(ja4App: string, ua: string): boolean {
  if (!ja4App) return false
  const app = ja4App.toLowerCase()
  const u   = ua.toLowerCase()

  const appIsScript  = /python|golang|curl|wget|java|node|ruby|postman|insomnia/.test(app)
  const appIsChrome  = /\bchrome\b|\bchromium\b/.test(app) && !/firefox|safari/.test(app)
  const appIsFirefox = /\bfirefox\b/.test(app)
  const appIsSafari  = /\bsafari\b/.test(app) && !/chrome|chromium/.test(app)
  const appIsBrowser = appIsChrome || appIsFirefox || appIsSafari

  const uaIsBrowser   = ua !== '' && isLikelyBrowserUA(ua)
  // uaIsChromium: matches all Chromium-based browsers (Chrome, Edge, Brave, Opera — all carry Chrome/NNN)
  const uaIsChromium  = /chrome\/\d/.test(u)
  const uaIsFirefox   = /firefox\/\d/.test(u)
  const uaIsSafari    = /safari\/\d/.test(u) && !uaIsChromium && !/firefox/.test(u)

  if (appIsScript  && uaIsBrowser)                      return true  // case 1
  if (appIsBrowser && !uaIsBrowser && ua !== '')        return true  // case 2
  if (appIsChrome  && uaIsBrowser  && !uaIsChromium)   return true  // case 3 : Chromium JA4 ≠ browser UA
  if (appIsFirefox && uaIsBrowser  && !uaIsFirefox) return true  // case 3 : Firefox JA4 ≠ browser UA
  if (appIsSafari  && uaIsBrowser  && !uaIsSafari)  return true  // case 3 : Safari JA4 ≠ browser UA
  return false
}

// ── TLS coherence signals (ClientHello raw data vs UA version) ────────────────
// Rules based on TLS structure properties that must match the declared browser.

interface TLSRaw {
  cipher_suites:        number[]
  supported_groups:     number[]
  signature_algorithms: number[]
  extensions:           number[]
}

function parseTLSFingerprint(raw: string): TLSRaw | null {
  if (!raw) return null
  try {
    const p = JSON.parse(raw)
    return {
      cipher_suites:        Array.isArray(p.cipher_suites)        ? p.cipher_suites        : [],
      supported_groups:     Array.isArray(p.supported_groups)     ? p.supported_groups     : [],
      signature_algorithms: Array.isArray(p.signature_algorithms) ? p.signature_algorithms : [],
      extensions:           Array.isArray(p.extensions)           ? p.extensions           : [],
    }
  } catch { return null }
}

// GREASE values (RFC 8701): both bytes equal, low nibble = 0xA (0x0A0A, 0x1A1A, …)
const isGREASE      = (n: number) => (n & 0xff) === (n >> 8) && (n & 0x0f) === 0x0a
const hasGREASE     = (list: number[]) => list.some(isGREASE)
// Post-quantum key exchange groups
const hasPQGroup    = (groups: number[]) => groups.includes(0x6399) || groups.includes(0x11ec)

function uaBrowserVersion(ua: string, browser: 'chrome' | 'firefox'): number {
  const m = ua.match(browser === 'chrome' ? /chrome\/(\d+)/i : /firefox\/(\d+)/i)
  return m ? parseInt(m[1], 10) : 0
}

function tlsCoherenceSignals(tlsRaw: TLSRaw | null, ua: string): Signal[] {
  const na = tlsRaw === null  // Go proxy absent — all N/A
  const cs  = tlsRaw?.cipher_suites        ?? []
  const grp = tlsRaw?.supported_groups     ?? []
  const sa  = tlsRaw?.signature_algorithms ?? []
  const ext = tlsRaw?.extensions           ?? []

  const uaIsChromium = /chrome\/\d/i.test(ua)
  const uaIsFirefox  = /firefox\/\d/i.test(ua)
  const uaIsBrowser  = isLikelyBrowserUA(ua)
  const chromeVer    = uaBrowserVersion(ua, 'chrome')
  const ffVer        = uaBrowserVersion(ua, 'firefox')

  return [
    {
      id: 'tls_grease_vs_firefox',
      label: 'GREASE TLS — UA Firefox',
      layer: 'tls_coherence',
      value: na ? 'N/A' : hasGREASE([...cs, ...grp]) ? 'GREASE detected' : 'No GREASE',
      suspicious: !na && hasGREASE([...cs, ...grp]) && uaIsFirefox,
      notApplicable: na || !uaIsFirefox,
      weight: 70,
      explanation: 'Firefox does not implement GREASE (RFC 8701). Chrome/Chromium inserts random GREASE values in cipher suites and groups to prevent TLS ossification.\n\nPresence of GREASE with a Firefox UA is a logical impossibility — it is a Chromium stack declaring itself as Firefox.',
    },
    {
      id: 'tls_ffdhe_absent_firefox',
      label: 'FFDHE absent — UA Firefox',
      layer: 'tls_coherence',
      value: na ? 'N/A' : grp.some(g => g === 0x0100 || g === 0x0101) ? 'FFDHE present' : 'FFDHE absent',
      suspicious: !na && !grp.some(g => g === 0x0100 || g === 0x0101) && uaIsFirefox,
      notApplicable: na || !uaIsFirefox,
      weight: 50,
      explanation: 'Firefox ≥ 76 always includes finite-field Diffie-Hellman groups (ffdhe2048 = 0x0100, ffdhe3072 = 0x0101) in its supported_groups.\n\nChrome and Safari never implement FFDHE. A Firefox UA without these groups reveals a non-Firefox TLS stack.',
    },
    {
      id: 'tls_ffdhe_vs_chrome',
      label: 'FFDHE present — UA Chrome',
      layer: 'tls_coherence',
      value: na ? 'N/A' : grp.some(g => g === 0x0100 || g === 0x0101) ? 'FFDHE present' : 'Absent (normal)',
      suspicious: !na && grp.some(g => g === 0x0100 || g === 0x0101) && uaIsChromium,
      notApplicable: na || !uaIsChromium,
      weight: 60,
      explanation: 'Chrome/Chromium has never included FFDHE (Finite Field Diffie-Hellman) groups in its supported_groups.\n\nThese groups (ffdhe2048, ffdhe3072) are exclusive to Firefox. Their presence with a Chromium UA is a logical impossibility.',
    },
    {
      id: 'tls_p521_groups_chrome',
      label: 'P-521 groups — UA Chrome',
      layer: 'tls_coherence',
      value: na ? 'N/A' : grp.includes(0x0019) ? 'P-521 present' : 'Absent (normal)',
      suspicious: !na && grp.includes(0x0019) && uaIsChromium,
      notApplicable: na || !uaIsChromium,
      weight: 50,
      explanation: 'Chrome removed the P-521 curve (secp521r1, 0x0019) from its supported_groups many years ago.\n\nFirefox and Safari still include P-521. Its presence with a Chrome/Chromium UA reveals a non-Chromium TLS stack (Firefox or a third-party library mimicking Firefox).',
    },
    {
      id: 'tls_pq_absent_chrome130',
      label: 'PQ absent — UA Chrome ≥ 130',
      layer: 'tls_coherence',
      value: na ? 'N/A' : hasPQGroup(grp) ? 'X25519MLKEM768 present' : 'No PQ group',
      suspicious: !na && !hasPQGroup(grp) && uaIsChromium && chromeVer >= 130,
      notApplicable: na || !uaIsChromium || chromeVer < 130,
      weight: 45,
      explanation: 'Chrome 124+ includes X25519MLKEM768 (0x11ec, NIST ML-KEM post-quantum) in its supported_groups. Chrome 116-123 used X25519Kyber768Draft00 (0x6399).\n\nA Chrome ≥ 130 UA without any post-quantum group does not match a real Chrome installation — spoofed TLS stack or falsified UA version.',
    },
    {
      id: 'tls_pq_absent_ff132',
      label: 'PQ absent — UA Firefox ≥ 132',
      layer: 'tls_coherence',
      value: na ? 'N/A' : hasPQGroup(grp) ? 'PQ group present' : 'No PQ group',
      suspicious: !na && !hasPQGroup(grp) && uaIsFirefox && ffVer >= 132,
      notApplicable: na || !uaIsFirefox || ffVer < 132,
      weight: 40,
      explanation: 'Firefox 132+ includes X25519MLKEM768 (0x11ec) in its supported_groups. Firefox 119-131 used X25519Kyber768Draft00 (0x6399).\n\nA Firefox ≥ 132 UA without a post-quantum group reveals a non-Firefox TLS stack or a falsified UA version.',
    },
    {
      id: 'tls_3des_modern',
      label: '3DES — modern browser',
      layer: 'tls_coherence',
      value: na ? 'N/A' : cs.includes(0x000a) ? '3DES present (0x000a)' : 'Absent (normal)',
      suspicious: !na && cs.includes(0x000a) && uaIsBrowser,
      notApplicable: na,
      weight: 35,
      explanation: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a) was removed by Chrome ≥ 67 (2018) and Firefox ≥ 44 (2016).\n\nIts presence in cipher suites with a modern browser UA reveals an old or non-standard TLS library, incompatible with any recent browser.',
    },
    {
      id: 'tls_p521_sigalg_chrome',
      label: 'secp521 sig_alg — UA Chrome',
      layer: 'tls_coherence',
      value: na ? 'N/A' : sa.includes(0x0603) ? 'ecdsa_secp521r1_sha512 present' : 'Absent (normal)',
      suspicious: !na && sa.includes(0x0603) && uaIsChromium,
      notApplicable: na || !uaIsChromium,
      weight: 30,
      explanation: 'Chrome does not list ecdsa_secp521r1_sha512 (0x0603) in its signature_algorithms.\n\nFirefox and Safari include this algorithm. Its presence with a Chrome/Chromium UA indicates a Firefox TLS stack or a third-party library that does not faithfully replicate the Chrome profile.',
    },
    {
      id: 'tls_compress_absent_chrome85',
      label: 'compress_certificate absent — Chrome ≥ 85',
      layer: 'tls_coherence',
      value: na ? 'N/A' : ext.includes(0x001b) ? 'Present' : 'Absent',
      suspicious: !na && !ext.includes(0x001b) && uaIsChromium && chromeVer >= 85,
      notApplicable: na || !uaIsChromium || chromeVer < 85,
      weight: 20,
      explanation: 'Chrome 85+ sends the compress_certificate extension (0x001b) to enable Brotli compression of TLS certificates, reducing their size by 30-40%.\n\nIts absence with a Chrome ≥ 85 UA is atypical — moderate signal as some network configurations may strip it.',
    },
    // tls_alps_absent_chrome91 removed: Chrome removed the ALPS extension (0x4469)
    // in late 2024, causing false positives on all modern Chrome/Edge builds.
  ]
}

// ── HTTP/2 SETTINGS fingerprint ───────────────────────────────────────────────
// Format from Go proxy: "1:65536;3:1000;4:6291456|15663105"
// Before |: SETTINGS frame entries  (id:value pairs separated by ;)
// After  |: WINDOW_UPDATE initial increment

interface H2Settings {
  headerTableSize:   number | null  // id 1
  enablePush:        number | null  // id 2
  maxConcurrentStr:  number | null  // id 3
  initialWindowSize: number | null  // id 4
  maxFrameSize:      number | null  // id 5
  windowUpdate:      number | null  // value after |
}

function parseH2Fingerprint(fp: string): H2Settings | null {
  if (!fp) return null
  const pipeIdx    = fp.indexOf('|')
  const settingsPart = pipeIdx >= 0 ? fp.slice(0, pipeIdx) : fp
  const windowPart   = pipeIdx >= 0 ? fp.slice(pipeIdx + 1) : ''
  const s: H2Settings = {
    headerTableSize: null, enablePush: null, maxConcurrentStr: null,
    initialWindowSize: null, maxFrameSize: null,
    windowUpdate: windowPart !== '' ? parseInt(windowPart, 10) : null,
  }
  for (const pair of settingsPart.split(';')) {
    const colon = pair.indexOf(':')
    if (colon < 0) continue
    const id  = parseInt(pair.slice(0, colon), 10)
    const val = parseInt(pair.slice(colon + 1), 10)
    if (isNaN(id) || isNaN(val)) continue
    switch (id) {
      case 1: s.headerTableSize   = val; break
      case 2: s.enablePush        = val; break
      case 3: s.maxConcurrentStr  = val; break
      case 4: s.initialWindowSize = val; break
      case 5: s.maxFrameSize      = val; break
    }
  }
  return s
}

// Identifies the browser behind HTTP/2 SETTINGS using the two most distinctive
// values: INITIAL_WINDOW_SIZE (id 4) and WINDOW_UPDATE.
//   Chrome  : IWS=6 291 456 · WU=15 663 105
//   Firefox : IWS=131 072   · WU=12 517 377
//   Safari  : IWS=4 194 304 · WU=10 485 760
function detectH2Browser(s: H2Settings): 'chrome' | 'firefox' | 'safari' | 'unknown' {
  const iws = s.initialWindowSize
  const wu  = s.windowUpdate
  if (iws === 6291456 || wu === 15663105) return 'chrome'
  if (iws === 131072  || wu === 12517377) return 'firefox'
  if (iws === 4194304 || wu === 10485760) return 'safari'
  return 'unknown'
}

// Returns true when the HTTP/2 browser identity contradicts the declared UA.
function h2BrowserVsUA(h2Browser: string, ua: string): boolean {
  if (h2Browser === 'unknown') return false
  const uaIsChromium = /chrome\/\d/i.test(ua)
  const uaIsFirefox  = /firefox\/\d/i.test(ua)
  const uaIsSafari   = /safari\/\d/i.test(ua) && !uaIsChromium && !uaIsFirefox
  if (h2Browser === 'chrome'  && !uaIsChromium) return true
  if (h2Browser === 'firefox' && !uaIsFirefox)  return true
  if (h2Browser === 'safari'  && !uaIsSafari)   return true
  return false
}

// ── POST flow (full JS payload) ───────────────────────────────────────────────

interface TLSContext {
  ja4:              string
  http2:            string
  tlsChanged:       boolean
  redisScore:       number
  httpUserAgent:    string   // User-Agent header received by the server
  ja4App:           string   // X-JA4-App: best available prediction (L1 > L2 > L3)
  ja4AppL1:         string   // X-JA4-App-L1: Level 1 exact DB match
  ja4AppL2:         string   // X-JA4-App-L2: Level 2 Part-B cipher family
  ja4AppL3:         string   // X-JA4-App-L3: Level 3 Part-A structural heuristic
  ja4IsThreat:      boolean  // X-JA4-Is-Threat: known malware/C2 fingerprint
  headerProfile:    string   // X-Header-Profile: comma-separated present browser-hint headers
  secChUaRaw:       string   // X-Sec-Ch-Ua-Raw: raw Sec-Ch-Ua value for version check
  secChUaPlatform:  string   // X-Sec-Ch-Ua-Platform: raw platform value, e.g. "Windows"
  secChUaMobile:    string   // X-Sec-Ch-Ua-Mobile: raw mobile flag, e.g. ?0 or ?1
  tlsFingerprint:   string   // X-TLS-Fingerprint: raw JSON from Go proxy (groups, ciphers, exts…)
}

export function evaluate(
  payload: FingerprintPayload,
  tls: TLSContext,
  sessionId: string,
  clientIp: string,
): AnalysisResult {

  const nav = payload.navigatorInfo

  const httpUA     = tls.httpUserAgent || nav.userAgent
  const uaOSHint   = uaOS(httpUA)
  const platOSHint = platformOS(nav.platform)
  const uaMismatch =
    uaOSHint !== 'unknown' &&
    platOSHint !== 'unknown' &&
    uaOSHint !== platOSHint &&
    !(uaOSHint === 'android' && platOSHint === 'linux')

  const ja4Anom    = tls.ja4 ? ja4Anomalies(tls.ja4, httpUA) : { lowVersion: false, noAlpn: false, fewCiphers: false, suspiciousCiphers: false, fewExts: false }
  const headerPen  = computeHeaderProfilePenalty(tls.headerProfile, httpUA, tls.secChUaRaw, tls.secChUaPlatform, tls.secChUaMobile)
  const h2Settings  = tls.http2 ? parseH2Fingerprint(tls.http2) : null
  const h2BrowserId = h2Settings ? detectH2Browser(h2Settings) : 'unknown'
  const h2Mismatch  = h2Settings ? h2BrowserVsUA(h2BrowserId, httpUA) : false

  const signals: Signal[] = [

    // ── JS layer ───────────────────────────────────────────────────────────

    {
      id: 'webdriver',
      label: 'WebDriver API',
      layer: 'automation',
      value: nav.webdriver ? 'Detected' : 'Not detected',
      suspicious: nav.webdriver,
      weight: 40,
      explanation: 'navigator.webdriver is a standard W3C WebDriver property. Browsers set it to true when controlled by Selenium, Playwright, or Puppeteer.\n\nMost sophisticated bots hide it via CDP (Object.defineProperty), but residual traces persist — notably $cdc_* properties on document.',
    },
    {
      id: 'automation_vars',
      label: 'Automation variables',
      layer: 'automation',
      value: nav.automationVars.length > 0 ? nav.automationVars.join(', ') : 'None',
      suspicious: nav.automationVars.length > 0,
      weight: 50,
      explanation: 'ChromeDriver injects properties on document whose names contain a random identifier specific to each version (e.g. $cdc_asdjflasutopfhvcZLmcfl_Array).\n\nPlaywright injects __playwright, Puppeteer __nightmare. These properties are rarely cleaned up by bots since they are less well known than navigator.webdriver.',
    },
    {
      id: 'untrusted_click',
      label: 'Synthetic click',
      layer: 'automation',
      value: payload.untrustedClick > 0  ? 'Detected'
           : payload.untrustedClick === 0 ? 'Real (isTrusted)'
           : 'Not observed',
      suspicious: payload.untrustedClick > 0,
      notApplicable: payload.untrustedClick < 0,
      weight: 60,
      explanation: 'Every real user event carries event.isTrusted = true (set by the browser itself).\n\nA click generated by script (element.click(), driver.execute_script, CDP Input.dispatchMouseEvent) has isTrusted = false — even if navigator.webdriver was hidden.\n\nBypassable only via Selenium ActionChains or OS-level simulation (PyAutoGUI, xdotool).',
    },
    {
      id: 'plugins',
      label: 'Browser plugins',
      layer: 'automation',
      value: `${nav.pluginsCount} plugin(s)`,
      suspicious: nav.pluginsCount === 0 && uaOSHint !== 'android' && uaOSHint !== 'ios',
      notApplicable: uaOSHint === 'android' || uaOSHint === 'ios',
      weight: 15,
      explanation: 'navigator.plugins lists installed plugins. Headless Chrome without extensions always returns 0 plugins.\n\nReal Chrome on Windows typically has 2-5 plugins (PDF Viewer, Chrome PDF Plugin, Native Client...). On mobile (Android/iOS) 0 plugins is normal — this signal is ignored.\n\nEasily bypassed by injecting fake plugins via CDP or launch options.',
    },
    {
      id: 'window_chrome',
      label: 'Chrome API',
      layer: 'automation',
      value: nav.windowChrome ? 'Present' : 'Absent',
      suspicious: !nav.windowChrome && nav.pluginsCount === 0 && uaOSHint !== 'android' && uaOSHint !== 'ios',
      weight: 10,
      explanation: 'window.chrome is a Chrome-proprietary object exposing internal APIs (chrome.runtime, chrome.loadTimes, chrome.csi...).\n\nHeadless Chrome before version 112 did not inject it. Since Chrome 112 (--headless=new), Google added it to reduce detectability — this signal is therefore less reliable on recent versions.',
    },
    {
      id: 'outer_width',
      label: 'Window size (outerWidth)',
      layer: 'automation',
      value: `${nav.outerWidth}px`,
      suspicious: nav.outerWidth === 0,
      weight: 15,
      explanation: 'window.outerWidth is the total width of the window including borders and title bar.\n\nHeadless Chrome without --window-size returns 0 because it has no physical window.\n\nBypassable: options.add_argument(\'--window-size=1920,1080\').',
    },
    {
      id: 'no_languages',
      label: 'Browser locales',
      layer: 'automation',
      value: nav.languages.length > 0 ? nav.languages.join(', ') : 'None',
      suspicious: nav.languages.length === 0,
      weight: 10,
      explanation: 'navigator.languages lists languages in order of preference (e.g. [\'en-US\', \'en\']).\n\nHeadless Chrome without locale configuration returns []. Bypassable via CDP: Network.setUserAgentOverride({ acceptLanguage: \'en-US,en\' }).',
    },
    {
      id: 'has_focus',
      label: 'Tab focus',
      layer: 'automation',
      value: nav.hasFocus ? 'Active' : 'Inactive',
      suspicious: !nav.hasFocus,
      weight: 10,
      explanation: 'document.hasFocus() returns true if the browser window is in the foreground.\n\nHeadless Chrome, having no real graphical window, returns false. Some frameworks patch it, but it remains a useful signal for unconfigured headless environments.',
    },
    {
      id: 'canvas',
      label: 'Canvas fingerprint',
      layer: 'fingerprint',
      value: payload.canvasHash === 'unavailable' ? 'Blocked' : payload.canvasHash.slice(0, 12) + '…',
      suspicious: payload.canvasHash === 'unavailable',
      weight: 10,
      explanation: 'Each GPU/driver/OS renders 2D text and shapes slightly differently (anti-aliasing, subpixel rendering). The resulting hash stably identifies the graphics environment.\n\n\'Blocked\' indicates the Canvas API is disabled: Tor Browser, CanvasBlocker extension, or Firefox with privacy.resistFingerprinting=true.',
    },
    {
      id: 'audio',
      label: 'Audio fingerprint',
      layer: 'fingerprint',
      value: payload.audioHash === 'unavailable' ? 'Blocked' : payload.audioHash.slice(0, 10) + '…',
      suspicious: payload.audioHash === 'unavailable',
      weight: 5,
      explanation: 'The OfflineAudioContext applies digital audio processing (oscillator + dynamic compressor). Differences in floating-point arithmetic precision across CPUs and audio drivers produce unique results per environment.\n\n\'Blocked\' may indicate Firefox resist.fingerprinting, an extension (Privacy Badger, uBlock strict mode), or a hardened browser.',
    },
    {
      id: 'webgl_renderer',
      label: 'WebGL renderer',
      layer: 'fingerprint',
      value: payload.webglRenderer || 'N/A',
      suspicious: isVirtualRenderer(payload.webglRenderer),
      weight: 25,
      explanation: 'WEBGL_debug_renderer_info exposes the real GPU name and its drivers.\n\nSoftware renderers (SwiftShader, llvmpipe, Mesa softpipe, VMware SVGA) indicate the absence of hardware GPU: headless server, virtual machine, Docker container.\n\nBypassable: chrome --use-gl=desktop enables the real GPU even in headless mode.',
    },
    {
      id: 'screen',
      label: 'Screen resolution',
      layer: 'device',
      value: `${payload.screenInfo.width}×${payload.screenInfo.height}`,
      suspicious: payload.screenInfo.width === 0 || payload.screenInfo.height === 0,
      weight: 20,
      explanation: 'screen.width/height return the physical screen resolution.\n\nA 0×0 resolution means no graphical display (pure headless). Bypassable: options.add_argument(\'--window-size=1920,1080\') or --force-device-scale-factor.',
    },
    {
      id: 'ua_platform',
      label: 'User-Agent / platform consistency',
      layer: 'device',
      value: uaMismatch ? `UA=${uaOSHint} / platform=${platOSHint}` : 'Consistent',
      suspicious: uaMismatch,
      weight: 20,
      explanation: 'navigator.platform exposes the OS detected by the JS engine (Win32, MacIntel, Linux x86_64...).\n\nIf the HTTP User-Agent claims Windows NT but platform returns Linux, there is spoofing: the bot modified the User-Agent without aligning navigator.platform.\n\nBots often forget this consistency as platform is less well known than the UA.',
    },
    {
      id: 'touch_vs_ua',
      label: 'Touch points vs mobile UA',
      layer: 'device',
      value: `${nav.touchPoints} pt(s)`,
      suspicious: (uaOSHint === 'android' || uaOSHint === 'ios') && nav.touchPoints === 0,
      notApplicable: uaOSHint !== 'android' && uaOSHint !== 'ios',
      weight: 25,
      explanation: 'navigator.maxTouchPoints returns the number of simultaneous touch contact points supported.\n\nA real mobile device (Android/iOS) always returns ≥ 1 (typically 5 or 10). A value of 0 on a mobile UA means the browser is running on a desktop without a touch screen and the UA was faked.\n\nNot applicable on desktop UA: non-touch machines legitimately have 0 points.',
    },

    // ── Behavior layer ─────────────────────────────────────────────────────

    {
      id: 'honeypot',
      label: 'Honeypot field',
      layer: 'behavior',
      value: payload.honeypot ? 'Filled!' : 'Empty',
      suspicious: payload.honeypot !== '',
      weight: 100,
      explanation: 'Invisible form field positioned off-screen (left: -9999px, opacity: 0). Real users never see or fill it.\n\nBots that automate form filling will systematically fill it. Weight 100: a single detection is enough to definitively classify the request as a bot.',
    },
    {
      id: 'mouse_moves',
      label: 'Mouse movement',
      layer: 'behavior',
      value: payload.mouse.moveCount < 0   ? 'Not measured'
           : payload.mouse.moveCount === 0  ? 'No movement'
           : `${payload.mouse.moveCount} events`,
      suspicious: payload.mouse.moveCount === 0,
      notApplicable: payload.mouse.moveCount < 0,
      weight: 20,
      explanation: 'Number of mousemove events recorded since page load.\n\nA bot executing actions without simulating movement will have 0 events. A human naturally generates dozens.\n\nNot measured during the initial challenge — click \'Update behavior\' after moving the mouse.',
    },
    {
      id: 'mouse_trajectory',
      label: 'Mouse trajectory',
      layer: 'behavior',
      value: payload.mouse.straightLineRatio < 0
        ? 'Not measured'
        : `${(payload.mouse.straightLineRatio * 100).toFixed(0)}% linear`,
      suspicious: payload.mouse.straightLineRatio > 0.98 && payload.mouse.moveCount > 10,
      notApplicable: payload.mouse.moveCount < 0,
      weight: 15,
      explanation: 'Ratio of direct distance to total arc of mouse movement. A human traces natural curves (ratio 0.6–0.9). A bot moving the mouse in a straight line approaches 1.0.\n\nSignificant only with more than 10 events. Bypassable with synthetic Bézier curves.',
    },
    {
      id: 'click_delay',
      label: 'Time to click',
      layer: 'behavior',
      value: payload.timeToClickMs === 0 ? 'Not measured' : `${payload.timeToClickMs} ms`,
      suspicious: payload.timeToClickMs > 0 && payload.timeToClickMs < 100,
      notApplicable: payload.timeToClickMs === 0,
      weight: 15,
      explanation: 'Time between page load and clicking \'Update behavior\'.\n\nA human typically takes 300 ms–3 s to read and click. Less than 100 ms is physiologically impossible — it is a script.\n\nNot measured during the initial challenge.',
    },
    {
      id: 'header_profile',
      label: 'Browser header profile',
      layer: 'behavior',
      value: headerPen.details,
      suspicious: headerPen.penalty > 0,
      weight: headerPen.penalty,
      explanation: 'Chromium systematically sends the sec-ch-ua + sec-ch-ua-mobile + sec-ch-ua-platform trio (Client Hints). Firefox never sends sec-ch-ua as it does not support Client Hints on navigation.\n\nAn inconsistency (sec-ch-ua absent on Chrome, incompatible version between sec-ch-ua and User-Agent, platform ≠ OS in UA) reveals HTTP header forgery.',
    },

    // ── TLS layer ──────────────────────────────────────────────────────────

    {
      id: 'ja4',
      label: 'JA4 Fingerprint',
      layer: 'tls',
      value: tls.ja4 || 'Not available (no proxy)',
      suspicious: false,
      notApplicable: !tls.ja4,
      weight: 0,
      explanation: 'TLS fingerprint captured in the ClientHello before the handshake by the Go proxy.\n\nFormat: t{version}{sni}{ciphers:02}{exts:02}{alpn}_{hash_ciphers}_{hash_exts}\nEx: t13d1516h2_8daaf6152771_xxx = TLS 1.3, SNI domain, 15 ciphers, 16 extensions, HTTP/2.\n\nEach TLS stack (Chrome, Firefox, Python-requests, curl) has a distinct and stable fingerprint.',
    },
    {
      id: 'tls_mismatch',
      label: 'TLS cross-session consistency',
      layer: 'tls',
      value: tls.tlsChanged ? 'Inconsistency detected' : 'Consistent',
      suspicious: tls.tlsChanged,
      weight: 10,
      explanation: 'The cipher suite hash (JA4 Part B) is stored on the first connection.\n\nA different Part B for the same session indicates: a TLS proxy intercepting connections, a cookie shared between different machines, or replay of a stolen cookie.\n\nNote: Parts A and C can legitimately vary (ALPN, extension order depending on resources).',
    },
    {
      id: 'ja4_known_threat',
      label: 'JA4: malicious tool',
      layer: 'tls',
      value: tls.ja4IsThreat ? `${tls.ja4App} (C2/malware)` : 'Not detected',
      suspicious: tls.ja4IsThreat,
      weight: 90,
      explanation: 'Certain JA4s are listed in the FoxIO database as malware signatures: Cobalt Strike beacons, IcedID, Pikabot, QakBot, Lumma Stealer, Sliver, Metasploit.\n\nThese tools implement their own TLS stack with characteristic configurations, difficult to spoof without modifying the binary.',
    },
    {
      id: 'ja4_known_script',
      label: 'JA4: script library',
      layer: 'tls',
      value: tls.ja4App || 'Unknown',
      suspicious: !tls.ja4IsThreat && tls.ja4App !== '' && /python|golang|curl|wget|java|node|ruby/.test(tls.ja4App.toLowerCase()),
      weight: 35,
      explanation: 'The JA4 database identifies HTTP libraries from their TLS fingerprint: python-requests, Go net/http, curl, wget, Java HttpClient, Node.js, Ruby Net::HTTP.\n\nEach library has different cipher suites and TLS extensions from a browser. A JA4 identified as a script/tool with a browser UA is a strong bot signal.',
    },
    {
      id: 'ja4_db_ua_mismatch',
      label: 'JA4 DB vs User-Agent',
      layer: 'tls',
      value: tls.ja4App ? `DB: ${tls.ja4App}` : 'Not in database',
      suspicious: ja4AppVsUA(tls.ja4App, httpUA),
      weight: 40,
      explanation: 'The JA4 database identifies software from its TLS fingerprint. If this identification does not match the declared User-Agent (JA4 = Python but UA = Chrome, JA4 = Chrome but UA = Firefox), there is forgery.\n\nThis is one of the hardest signals to bypass: changing the UA does not modify the underlying TLS stack.',
    },
    {
      id: 'ja4_tls_version',
      label: 'Version TLS vs UA',
      layer: 'tls',
      value: tls.ja4 ? `TLS 1.${parseJA4PartA(tls.ja4)?.version === '13' ? 3 : parseJA4PartA(tls.ja4)?.version === '12' ? 2 : '?'}` : 'N/A',
      suspicious: ja4Anom.lowVersion,
      weight: 15,
      explanation: 'TLS 1.3 has been mandatory since Chrome 84 (2020) and Firefox 74 (2020).\n\nA client claiming to be a modern browser but only using TLS 1.2 is using a third-party TLS library: Python-requests, curl, pre-JDK11 Java, or an embedded library.',
    },
    {
      id: 'ja4_no_alpn',
      label: 'ALPN missing',
      layer: 'tls',
      value: tls.ja4 ? (parseJA4PartA(tls.ja4)?.alpn ?? 'N/A') : 'N/A',
      suspicious: ja4Anom.noAlpn,
      weight: 10,
      explanation: 'ALPN (Application-Layer Protocol Negotiation) allows negotiating the application protocol (h2, http/1.1) in the TLS ClientHello.\n\nAll modern HTTP clients use it. Absence of ALPN (\'00\' in JA4) signals a minimalist TLS tool, a port scanner, or a misconfigured client.',
    },
    {
      id: 'ja4_few_ciphers',
      label: 'Cipher suite count',
      layer: 'tls',
      value: tls.ja4 ? `${parseJA4PartA(tls.ja4)?.ciphers ?? 'N/A'} suites` : 'N/A',
      suspicious: ja4Anom.fewCiphers,
      weight: 15,
      explanation: 'Browsers offer 15–20 cipher suites in their ClientHello.\n\nFewer than 5 suites indicates a minimal TLS library (scanner, testing tool, custom client). This signal is nearly impossible to false-positive on a real browser.',
    },
    {
      // Fires only when JA4 not in DB — avoids double-counting with ja4_db_ua_mismatch
      id: 'ja4_suspicious_ciphers',
      label: 'Insufficient cipher suites for a browser',
      layer: 'tls',
      value: tls.ja4 ? `${parseJA4PartA(tls.ja4)?.ciphers ?? 'N/A'} suites` : 'N/A',
      suspicious: ja4Anom.suspiciousCiphers && !tls.ja4App,
      weight: 20,
      explanation: '5–9 cipher suites with a declared browser UA.\n\nReal browsers offer 15–20. This limited count is characteristic of libraries like Python-requests or curl that only implement the suites they natively support.',
    },
    {
      // Fires only when JA4 not in DB — avoids double-counting with ja4_db_ua_mismatch
      id: 'ja4_few_exts',
      label: 'Insufficient TLS extensions for a browser',
      layer: 'tls',
      value: tls.ja4 ? `${parseJA4PartA(tls.ja4)?.exts ?? 'N/A'} extensions` : 'N/A',
      suspicious: ja4Anom.fewExts && !tls.ja4App,
      weight: 15,
      explanation: 'Browsers include 8–16 TLS extensions in the ClientHello (SNI, ALPN, supported_groups, session_ticket, etc.).\n\nFewer than 6 extensions with a browser UA is inconsistent — simplistic HTTP libraries do not implement all these standard extensions.',
    },
    {
      id: 'h2_settings_vs_ua',
      label: 'HTTP/2 SETTINGS vs UA',
      layer: 'tls',
      value: !h2Settings
        ? 'N/A'
        : h2BrowserId === 'unknown'
          ? `IWS=${h2Settings.initialWindowSize ?? '?'} WU=${h2Settings.windowUpdate ?? '?'}`
          : `${h2BrowserId} (IWS=${h2Settings.initialWindowSize})`,
      suspicious: h2Mismatch,
      notApplicable: !tls.http2,
      weight: 35,
      explanation: 'HTTP/2 SETTINGS (initial handshake frame) are as distinctive as the TLS JA4.\n\nReference values:\n• Chrome  : INITIAL_WINDOW_SIZE=6 291 456 · WINDOW_UPDATE=15 663 105\n• Firefox : INITIAL_WINDOW_SIZE=131 072   · WINDOW_UPDATE=12 517 377\n• Safari  : INITIAL_WINDOW_SIZE=4 194 304 · WINDOW_UPDATE=10 485 760\n\nA mismatch (e.g. Firefox SETTINGS + Chrome UA) reveals a tool that changed the User-Agent without patching the HTTP/2 layer — the network stack behavior betrays the true identity.',
    },

    // ── Headless layer ─────────────────────────────────────────────────────

    {
      id: 'headless_speech',
      label: 'Speech synthesis voices',
      layer: 'headless',
      value: payload.headless.speechVoices < 0 ? 'API absent'
           : payload.headless.speechVoices === 0 ? 'No voices'
           : `${payload.headless.speechVoices} voice(s)`,
      suspicious: payload.headless.speechVoices <= 0 && uaOSHint !== 'android' && uaOSHint !== 'ios',
      notApplicable: uaOSHint === 'android' || uaOSHint === 'ios',
      weight: 30,
      explanation: 'speechSynthesis.getVoices() returns the TTS voices installed on the OS.\n\nA headless browser without an audio subsystem returns 0 voices. Real Chrome on Windows typically has 20–40 (David, Zira, Hazel...). This API cannot be faked without a properly configured OS audio stack.\n\nOn a real PC browser, speechSynthesis is always defined — its absence (API absent) is itself a strong headless indicator.\n\nNot applicable on mobile (Android/iOS): mobile browsers often return 0 voices without being headless.',
    },
    {
      id: 'headless_media_devices',
      label: 'Media devices',
      layer: 'headless',
      value: payload.headless.mediaDeviceCount < 0 ? 'API absent'
           : `${payload.headless.mediaDeviceCount} device(s)`,
      suspicious: payload.headless.mediaDeviceCount === 0,
      notApplicable: payload.headless.mediaDeviceCount < 0,
      weight: 25,
      explanation: 'navigator.mediaDevices.enumerateDevices() lists audio/video devices.\n\nEven without permission, a real browser returns the device types (audioinput, audiooutput, videoinput) with an empty deviceId. A headless without a media subsystem returns [] — strong signal of a virtualized environment.',
    },
    {
      id: 'headless_native_patch',
      label: 'Patched native functions',
      layer: 'headless',
      value: payload.headless.patchedFunctions.length === 0 ? 'Intact'
           : payload.headless.patchedFunctions.join(', '),
      suspicious: payload.headless.patchedFunctions.length > 0,
      weight: 45,
      explanation: 'Detects injections from pyppeteer_stealth / puppeteer-extra-plugin-stealth via two families of checks:\n\n1. Native toString (3 methods): direct Function.prototype.toString, recursive self-check, and cross-realm via iframe. Detects patched getters (webdriver, userAgent, permissions.query).\n\n2. Structural integrity (prototype/instanceof): navigator.plugins must be a real PluginArray, each entry a real Plugin instance, mimeTypes consistent with plugins. window.chrome.csi/loadTimes must exist. Stealth injects fake arrays/objects that fail these type checks.',
    },
    {
      id: 'headless_stack_trace',
      label: 'Stack trace artifacts',
      layer: 'headless',
      value: payload.headless.stackTraceArtifacts.length === 0 ? 'No artifacts'
           : payload.headless.stackTraceArtifacts.join(', '),
      suspicious: payload.headless.stackTraceArtifacts.length > 0,
      weight: 60,
      explanation: 'When automation tools (Puppeteer, Playwright, Selenium) inject scripts via CDP (page.evaluate / evaluateOnNewDocument), V8 compiles these scripts with distinctive source URLs: pptr://, __puppeteer_evaluation_script__, playwright://, etc.\n\nScraping extensions (Tampermonkey, Greasemonkey, Violentmonkey) appear via chrome-extension:// or moz-extension:// when one of their scripts is in the call chain (patched getter, intercepted fetch, injected event handler).\n\nA "captureStackTrace-patched" artifact indicates the tool replaced Error.captureStackTrace (native V8 API) to purge its own frames from stacks — active evasion behavior.',
    },

    // ── TLS coherence layer ───────────────────────────────────────────────────
    ...tlsCoherenceSignals(parseTLSFingerprint(tls.tlsFingerprint), httpUA),
  ]

  const jsScore = signals.reduce((acc, s) => acc + (s.suspicious ? s.weight : 0), 0)
  const score   = Math.round(jsScore + Math.min(30, tls.redisScore))

  const verdict: AnalysisResult['verdict'] =
    score >= 60 ? 'bot' : score >= 25 ? 'suspect' : 'human'

  return {
    sessionId,
    score,
    verdict,
    signals,
    ja4:              tls.ja4,
    http2Fingerprint: tls.http2,
    clientIp,
    timestamp:        Date.now(),
    userAgent:        httpUA,
    ja4App:           tls.ja4App,
    ja4AppL1:         tls.ja4AppL1,
    ja4AppL2:         tls.ja4AppL2,
    ja4AppL3:         tls.ja4AppL3,
  }
}

// ── GET-only analysis ────────────────────────────────────────────────────────
// Signals available without JS: HTTP headers + TLS (via Go proxy) + Redis session.

// Tier-3 UA blacklist: known scripting / testing tools.
// Combined with the whitelist check (isLikelyBrowserUA) this gives 3 tiers:
//   1. Known browser structure                  → ok
//   2. Unknown UA, not a browser               → suspicious  (+20)
//   3. Known bot/tool UA OR absent             → very suspicious (+50)
const BOT_UA_PATTERNS = [
  'python-requests', 'python-urllib', 'python-httpx',
  'curl', 'wget', 'httpie',
  'scrapy', 'playwright', 'puppeteer', 'selenium',
  'go-http-client', 'java/', 'apache-httpclient',
  'okhttp', 'node-fetch', 'axios', 'got/',
  'libwww-perl', 'lwp-useragent',
  'postmanruntime', 'insomnia',
]

function isBotUA(ua: string): boolean {
  const u = ua.toLowerCase()
  return BOT_UA_PATTERNS.some(p => u.includes(p))
}

export interface HeadersContext {
  ja4:             string
  http2:           string
  tlsChanged:      boolean
  redisScore:      number
  userAgent:       string
  acceptLanguage:  string
  acceptEncoding:  string
  ja4App:          string   // X-JA4-App: best available prediction (L1 > L2 > L3)
  ja4AppL1:        string   // X-JA4-App-L1: Level 1 exact DB match
  ja4AppL2:        string   // X-JA4-App-L2: Level 2 Part-B cipher family
  ja4AppL3:        string   // X-JA4-App-L3: Level 3 Part-A structural heuristic
  ja4IsThreat:     boolean  // X-JA4-Is-Threat header from Go proxy
  headerProfile:   string   // X-Header-Profile: comma-separated present browser-hint headers
  secChUaRaw:      string   // X-Sec-Ch-Ua-Raw: raw Sec-Ch-Ua value for version check
  secChUaPlatform: string   // X-Sec-Ch-Ua-Platform: raw platform value, e.g. "Windows"
  secChUaMobile:   string   // X-Sec-Ch-Ua-Mobile: raw mobile flag, e.g. ?0 or ?1
  tlsFingerprint:  string   // X-TLS-Fingerprint: raw JSON from Go proxy
}

export function evaluateGet(
  ctx: HeadersContext,
  sessionId: string,
  clientIp: string,
): AnalysisResult {
  const ua        = ctx.userAgent
  const ja4Anom   = ctx.ja4 ? ja4Anomalies(ctx.ja4, ua) : { lowVersion: false, noAlpn: false, fewCiphers: false, suspiciousCiphers: false, fewExts: false }
  const headerPen = computeHeaderProfilePenalty(ctx.headerProfile, ua, ctx.secChUaRaw, ctx.secChUaPlatform, ctx.secChUaMobile)
  const h2Settings  = ctx.http2 ? parseH2Fingerprint(ctx.http2) : null
  const h2BrowserId = h2Settings ? detectH2Browser(h2Settings) : 'unknown'
  const h2Mismatch  = h2Settings ? h2BrowserVsUA(h2BrowserId, ua) : false

  const signals: Signal[] = [

    // ── TLS layer ────────────────────────────────────────────────────────────

    {
      id: 'ja4',
      label: 'JA4 Fingerprint',
      layer: 'tls',
      value: ctx.ja4 || 'Not available (no proxy)',
      suspicious: false,
      notApplicable: !ctx.ja4,
      weight: 0,
      explanation: 'TLS fingerprint captured in the ClientHello before the handshake by the Go proxy.\n\nFormat: t{version}{sni}{ciphers:02}{exts:02}{alpn}_{hash_ciphers}_{hash_exts}\nEx: t13d1516h2_8daaf6152771_xxx = TLS 1.3, SNI domain, 15 ciphers, 16 extensions, HTTP/2.\n\nEach TLS stack (Chrome, Firefox, Python-requests, curl) has a distinct and stable fingerprint.',
    },
    {
      id: 'tls_mismatch',
      label: 'TLS cross-session consistency',
      layer: 'tls',
      value: ctx.tlsChanged ? 'Inconsistency detected' : 'Consistent',
      suspicious: ctx.tlsChanged,
      weight: 10,
      explanation: 'The cipher suite hash (JA4 Part B) is stored on the first connection.\n\nA different Part B for the same session indicates: a TLS proxy intercepting connections, a cookie shared between different machines, or replay of a stolen cookie.',
    },
    {
      id: 'ja4_known_threat',
      label: 'JA4: malicious tool',
      layer: 'tls',
      value: ctx.ja4IsThreat ? `${ctx.ja4App} (C2/malware)` : 'Not detected',
      suspicious: ctx.ja4IsThreat,
      weight: 90,
      explanation: 'Certain JA4s are listed in the FoxIO database as malware signatures: Cobalt Strike beacons, IcedID, Pikabot, QakBot, Lumma Stealer, Sliver, Metasploit.\n\nThese tools implement their own TLS stack with characteristic configurations, difficult to spoof without modifying the binary.',
    },
    {
      id: 'ja4_known_script',
      label: 'JA4: script library',
      layer: 'tls',
      value: ctx.ja4App || 'Unknown',
      suspicious: !ctx.ja4IsThreat && ctx.ja4App !== '' && /python|golang|curl|wget|java|node|ruby/.test(ctx.ja4App.toLowerCase()),
      weight: 35,
      explanation: 'The JA4 database identifies HTTP libraries from their TLS fingerprint: python-requests, Go net/http, curl, wget, Java HttpClient, Node.js, Ruby Net::HTTP.\n\nEach library has different cipher suites and TLS extensions from a browser. A JA4 identified as a script/tool with a browser UA is a strong bot signal.',
    },
    {
      id: 'ja4_db_ua_mismatch',
      label: 'JA4 DB vs User-Agent',
      layer: 'tls',
      value: ctx.ja4App ? `DB: ${ctx.ja4App}` : 'Not in database',
      suspicious: ja4AppVsUA(ctx.ja4App, ua),
      weight: 40,
      explanation: 'The JA4 database identifies software from its TLS fingerprint. If this identification does not match the declared User-Agent (JA4 = Python but UA = Chrome, JA4 = Chrome but UA = Firefox), there is forgery.\n\nThis is one of the hardest signals to bypass: changing the UA does not modify the underlying TLS stack.',
    },
    {
      id: 'ja4_tls_version',
      label: 'Version TLS vs UA',
      layer: 'tls',
      value: ctx.ja4 ? `TLS 1.${parseJA4PartA(ctx.ja4)?.version === '13' ? 3 : parseJA4PartA(ctx.ja4)?.version === '12' ? 2 : '?'}` : 'N/A',
      suspicious: ja4Anom.lowVersion,
      weight: 15,
      explanation: 'TLS 1.3 has been mandatory since Chrome 84 (2020) and Firefox 74 (2020).\n\nA client claiming to be a modern browser but only using TLS 1.2 is using a third-party TLS library: Python-requests, curl, pre-JDK11 Java, or an embedded library.',
    },
    {
      id: 'ja4_no_alpn',
      label: 'ALPN missing',
      layer: 'tls',
      value: ctx.ja4 ? (parseJA4PartA(ctx.ja4)?.alpn ?? 'N/A') : 'N/A',
      suspicious: ja4Anom.noAlpn,
      weight: 10,
      explanation: 'ALPN (Application-Layer Protocol Negotiation) allows negotiating the application protocol (h2, http/1.1) in the TLS ClientHello.\n\nAll modern HTTP clients use it. Absence of ALPN (\'00\' in JA4) signals a minimalist TLS tool, a port scanner, or a misconfigured client.',
    },
    {
      id: 'ja4_few_ciphers',
      label: 'Cipher suite count',
      layer: 'tls',
      value: ctx.ja4 ? `${parseJA4PartA(ctx.ja4)?.ciphers ?? 'N/A'} suites` : 'N/A',
      suspicious: ja4Anom.fewCiphers,
      weight: 15,
      explanation: 'Browsers offer 15–20 cipher suites in their ClientHello.\n\nFewer than 5 suites indicates a minimal TLS library (scanner, testing tool, custom client). This signal is nearly impossible to false-positive on a real browser.',
    },
    {
      // Fires only when JA4 not in DB — avoids double-counting with ja4_db_ua_mismatch
      id: 'ja4_suspicious_ciphers',
      label: 'Insufficient cipher suites for a browser',
      layer: 'tls',
      value: ctx.ja4 ? `${parseJA4PartA(ctx.ja4)?.ciphers ?? 'N/A'} suites` : 'N/A',
      suspicious: ja4Anom.suspiciousCiphers && !ctx.ja4App,
      weight: 20,
      explanation: '5–9 cipher suites with a declared browser UA.\n\nReal browsers offer 15–20. This limited count is characteristic of libraries like Python-requests or curl that only implement the suites they natively support.',
    },
    {
      // Fires only when JA4 not in DB — avoids double-counting with ja4_db_ua_mismatch
      id: 'ja4_few_exts',
      label: 'Insufficient TLS extensions for a browser',
      layer: 'tls',
      value: ctx.ja4 ? `${parseJA4PartA(ctx.ja4)?.exts ?? 'N/A'} extensions` : 'N/A',
      suspicious: ja4Anom.fewExts && !ctx.ja4App,
      weight: 15,
      explanation: 'Browsers include 8–16 TLS extensions in the ClientHello (SNI, ALPN, supported_groups, session_ticket, etc.).\n\nFewer than 6 extensions with a browser UA is inconsistent — simplistic HTTP libraries do not implement all these standard extensions.',
    },
    {
      id: 'h2_settings_vs_ua',
      label: 'HTTP/2 SETTINGS vs UA',
      layer: 'tls',
      value: !h2Settings
        ? 'N/A'
        : h2BrowserId === 'unknown'
          ? `IWS=${h2Settings.initialWindowSize ?? '?'} WU=${h2Settings.windowUpdate ?? '?'}`
          : `${h2BrowserId} (IWS=${h2Settings.initialWindowSize})`,
      suspicious: h2Mismatch,
      notApplicable: !ctx.http2,
      weight: 35,
      explanation: 'HTTP/2 SETTINGS (initial handshake frame) are as distinctive as the TLS JA4.\n\nReference values:\n• Chrome  : INITIAL_WINDOW_SIZE=6 291 456 · WINDOW_UPDATE=15 663 105\n• Firefox : INITIAL_WINDOW_SIZE=131 072   · WINDOW_UPDATE=12 517 377\n• Safari  : INITIAL_WINDOW_SIZE=4 194 304 · WINDOW_UPDATE=10 485 760\n\nA mismatch (e.g. Firefox SETTINGS + Chrome UA) reveals a tool that changed the User-Agent without patching the HTTP/2 layer — the network stack behavior betrays the true identity.',
    },

    // ── JS layer (headers only) ───────────────────────────────────────────────

    {
      // Tier 3 — UA absent or known tool/bot (very suspicious)
      id: 'ua_known_bot',
      label: 'Known tool/bot User-Agent',
      layer: 'automation',
      value: ua || '(absent)',
      suspicious: ua === '' || isBotUA(ua),
      weight: 50,
      explanation: 'User-Agent absent or identified as a known scraping/testing tool.\n\nList: python-requests, curl, wget, Scrapy, Playwright, Puppeteer, Selenium, Go-http-client, Java, Apache HttpClient, OkHttp, node-fetch, axios, Postman, Insomnia...\n\nWeight 50: strong signal when combined with consistent JA4.',
    },
    {
      // Tier 2 — UA present but unknown: neither recognized browser nor listed tool (suspicious)
      id: 'ua_not_browser',
      label: 'Unrecognized User-Agent',
      layer: 'automation',
      value: ua || '(absent)',
      suspicious: ua !== '' && !isBotUA(ua) && !isLikelyBrowserUA(ua),
      weight: 40,
      explanation: 'User-Agent present but matches neither a known browser (Mozilla/5.0 + Chrome/Firefox/Safari/Edge structure) nor a tool in the blacklist.\n\nTypical of a custom HTTP client or a bot that modified its UA without adopting a consistent browser profile.',
    },

    // ── Behavior layer (headers only) ────────────────────────────────────────

    {
      id: 'accept_language',
      label: 'Accept-Language',
      layer: 'behavior',
      value: ctx.acceptLanguage || '(absent)',
      suspicious: ctx.acceptLanguage === '',
      weight: 10,
      explanation: 'Accept-Language indicates the client\'s preferred languages (e.g. en-US,en;q=0.9).\n\nAll browsers send it systematically. Absent = script request without a full browser profile.',
    },
    {
      id: 'accept_encoding',
      label: 'Accept-Encoding',
      layer: 'behavior',
      value: ctx.acceptEncoding || '(absent)',
      suspicious: ctx.acceptEncoding === '',
      weight: 5,
      explanation: 'Accept-Encoding lists supported compression algorithms (gzip, deflate, br).\n\nAll modern HTTP clients send it to reduce bandwidth. Absent = basic or misconfigured HTTP client.',
    },
    {
      id: 'header_profile',
      label: 'Browser header profile',
      layer: 'behavior',
      value: headerPen.details,
      suspicious: headerPen.penalty > 0,
      weight: headerPen.penalty,
      explanation: 'Chromium systematically sends the sec-ch-ua + sec-ch-ua-mobile + sec-ch-ua-platform trio (Client Hints). Firefox never sends sec-ch-ua.\n\nAn inconsistency (sec-ch-ua absent on Chrome, incompatible version, platform ≠ OS in UA) reveals HTTP header forgery.',
    },

    // ── TLS coherence layer ───────────────────────────────────────────────────
    ...tlsCoherenceSignals(parseTLSFingerprint(ctx.tlsFingerprint), ua),
  ]

  const headersScore = signals.reduce((acc, s) => acc + (s.suspicious ? s.weight : 0), 0)
  const score        = Math.round(headersScore + Math.min(30, ctx.redisScore))

  const verdict: AnalysisResult['verdict'] =
    score >= 60 ? 'bot' : score >= 25 ? 'suspect' : 'human'

  return {
    sessionId,
    score,
    verdict,
    signals,
    ja4:              ctx.ja4,
    http2Fingerprint: ctx.http2,
    clientIp,
    timestamp:        Date.now(),
    userAgent:        ua,
    ja4App:           ctx.ja4App,
    ja4AppL1:         ctx.ja4AppL1,
    ja4AppL2:         ctx.ja4AppL2,
    ja4AppL3:         ctx.ja4AppL3,
  }
}
