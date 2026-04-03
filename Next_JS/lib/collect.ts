'use client'
// Client-side utilities for collecting lightweight fingerprint data.
// Heavy collection (canvas, audio) runs in workers/fingerprint.worker.ts

import type { NavigatorInfo, ScreenInfo, MouseStats, HeadlessInfo } from './types'

// Known globals injected by automation frameworks.
const AUTOMATION_GLOBALS = [
  // Selenium / ChromeDriver
  'cdc_adoQpoasnfa76pfcZLmcfl_Array',
  'cdc_adoQpoasnfa76pfcZLmcfl_Promise',
  'cdc_adoQpoasnfa76pfcZLmcfl_Symbol',
  '__webdriver_evaluate',
  '__selenium_evaluate',
  '__webdriver_script_function',
  '__webdriver_script_func',
  '__webdriver_script_element',
  '__fxdriver_evaluate',
  '__driver_unwrapped',
  '__webdriver_unwrapped',
  '__driver_evaluate',
  '__selenium_unwrapped',
  '__fxdriver_unwrapped',
  // Playwright
  '__playwright',
  '__pw_manual',
  // Puppeteer / Nightmare
  '__nightmare',
  '_phantom',
  '__phantomas',
  'callPhantom',
  // Generic
  'domAutomation',
  'domAutomationController',
]

function detectAutomationVars(): string[] {
  const found: string[] = []
  const w = window as unknown as Record<string, unknown>
  for (const key of AUTOMATION_GLOBALS) {
    if (w[key] !== undefined) found.push(key)
  }
  // ChromeDriver injects $cdc_* own properties onto document (version-specific random suffix)
  try {
    const cdcKeys = Object.getOwnPropertyNames(document).filter(k => k.startsWith('$cdc_'))
    found.push(...cdcKeys)
  } catch { /* ignore */ }
  return found
}

export function collectNavigator(): NavigatorInfo {
  const n = navigator
  return {
    webdriver:        n.webdriver ?? false,
    platform:         n.platform,
    language:         n.language,
    languages:        Array.from(n.languages ?? []),
    hardwareConcurrency: n.hardwareConcurrency ?? 0,
    deviceMemory:     (n as Navigator & { deviceMemory?: number }).deviceMemory,
    pluginsCount:     n.plugins?.length ?? 0,
    cookieEnabled:    n.cookieEnabled,
    doNotTrack:       n.doNotTrack,
    touchPoints:      n.maxTouchPoints ?? 0,
    windowChrome:     typeof (window as Window & { chrome?: unknown }).chrome !== 'undefined',
    outerWidth:       window.outerWidth,
    hasFocus:         document.hasFocus(),
    automationVars:   detectAutomationVars(),
    userAgent:        n.userAgent,
  }
}

export function collectScreen(): ScreenInfo {
  return {
    width:       screen.width,
    height:      screen.height,
    availWidth:  screen.availWidth,
    availHeight: screen.availHeight,
    colorDepth:  screen.colorDepth,
    pixelRatio:  window.devicePixelRatio ?? 1,
  }
}

export function collectWebGL(): { vendor: string; renderer: string } {
  try {
    const canvas = document.createElement('canvas')
    const gl =
      (canvas.getContext('webgl') as WebGLRenderingContext | null) ??
      (canvas.getContext('experimental-webgl') as WebGLRenderingContext | null)
    if (!gl) return { vendor: 'none', renderer: 'none' }

    const ext = gl.getExtension('WEBGL_debug_renderer_info')
    return {
      vendor: ext
        ? String(gl.getParameter(ext.UNMASKED_VENDOR_WEBGL))
        : String(gl.getParameter(gl.VENDOR)),
      renderer: ext
        ? String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL))
        : String(gl.getParameter(gl.RENDERER)),
    }
  } catch {
    return { vendor: 'error', renderer: 'error' }
  }
}

// ── Audio fingerprint ───────────────────────────────────────────────────────
// Must run on the main thread — OfflineAudioContext is unavailable in Workers
// on Firefox and Safari (security restriction on audio processing off-thread).

export async function collectAudio(): Promise<string> {
  try {
    const ctx = new OfflineAudioContext(1, 44100, 44100)

    const osc = ctx.createOscillator()
    const comp = ctx.createDynamicsCompressor()
    comp.threshold.value = -50
    comp.knee.value = 40
    comp.ratio.value = 12
    comp.attack.value = 0
    comp.release.value = 0.25

    osc.connect(comp)
    comp.connect(ctx.destination)
    osc.start(0)
    osc.stop(0.1)

    const buffer = await ctx.startRendering()
    const data = buffer.getChannelData(0)

    let sum = 0
    for (let i = 4500; i < Math.min(5000, data.length); i++) {
      sum += Math.abs(data[i])
    }

    return sum.toFixed(10)
  } catch {
    return 'unavailable'
  }
}

// ── Headless detection ────────────────────────────────────────────────────────

// speechSynthesis.getVoices(): returns [] in headless (no OS audio subsystem).
// We wait for the onvoiceschanged event with a 500 ms timeout.
async function collectSpeechVoices(): Promise<number> {
  if (typeof window.speechSynthesis === 'undefined') return -1
  const immediate = window.speechSynthesis.getVoices()
  if (immediate.length > 0) return immediate.length
  return new Promise<number>(resolve => {
    const timer = setTimeout(() => {
      window.speechSynthesis.onvoiceschanged = null
      resolve(0)
    }, 500)
    window.speechSynthesis.onvoiceschanged = () => {
      clearTimeout(timer)
      window.speechSynthesis.onvoiceschanged = null
      resolve(window.speechSynthesis.getVoices().length)
    }
  })
}

// enumerateDevices(): returns [] in headless (no camera/mic/speaker).
// Even without permission, a real browser returns device kinds with an empty deviceId.
async function collectMediaDevices(): Promise<number> {
  if (!navigator.mediaDevices?.enumerateDevices) return -1
  try {
    const devices = await navigator.mediaDevices.enumerateDevices()
    return devices.length
  } catch {
    return -1
  }
}

// ── Stack trace artifact detection ──────────────────────────────────────────
// When automation tools (Puppeteer, Playwright, Selenium) inject scripts via CDP
// (evaluateOnNewDocument / Runtime.evaluate), these scripts are compiled by V8
// with distinctive source URLs (pptr://, playwright://, etc.) that appear in
// stack traces when they are in the call chain.
//
// Trigger cases:
//   - bot calls page.evaluate() → our code → new Error().stack contains the automation URL
//   - preloaded script is in the call chain (e.g. patched getter, synthetic event)
//   - Error.captureStackTrace replaced to purge automation frames
//   - Tampermonkey/Greasemonkey/Violentmonkey extension with script in the call chain:
//     its source URL chrome-extension://xyz/... or moz-extension://xyz/... appears

const STACK_ARTIFACT_PATTERNS: Array<{ test: string; label: string }> = [
  { test: '__puppeteer_evaluation_script__', label: 'puppeteer'        },
  { test: 'pptr://',                         label: 'puppeteer'        },
  { test: '__playwright_evaluation_script__', label: 'playwright'      },
  { test: 'playwright://',                   label: 'playwright'       },
  { test: '__selenium_evaluate',             label: 'selenium'         },
  { test: '__webdriver_evaluate',            label: 'webdriver'        },
  { test: 'cdp://',                          label: 'cdp'              },
  { test: 'chrome-extension://',             label: 'chrome-extension' },
  { test: 'moz-extension://',               label: 'moz-extension'    },
]

function detectStackTraceArtifacts(): string[] {
  const found = new Set<string>()

  // Method 1: string stack (all browsers)
  // Catches contexts where automation code is in the call chain.
  try {
    const stack = new Error().stack ?? ''
    for (const { test, label } of STACK_ARTIFACT_PATTERNS) {
      if (stack.includes(test)) found.add(label)
    }
  } catch { /* ignore */ }

  // Method 2: structured V8 frames (Chrome/Edge only)
  // Error.prepareStackTrace returns raw CallSite objects — getFileName() exposes the
  // exact source URL of the script compiled by V8, even if it doesn't appear in toString.
  type CallSite = { getFileName(): string | null }
  type ErrCtor = typeof Error & { prepareStackTrace?: (e: Error, s: CallSite[]) => unknown }
  const E = Error as ErrCtor
  const orig = E.prepareStackTrace
  try {
    E.prepareStackTrace = (_, frames) => frames
    const err = new Error()
    const frames = err.stack as unknown as CallSite[]  // .stack triggers prepareStackTrace
    if (Array.isArray(frames)) {
      for (const frame of frames) {
        const fn = frame.getFileName?.() ?? ''
        for (const { test, label } of STACK_ARTIFACT_PATTERNS) {
          if (fn.includes(test)) found.add(label)
        }
      }
    }
  } finally {
    E.prepareStackTrace = orig
  }

  // Method 3: detection of patched Error.captureStackTrace
  // Some tools replace this native V8 API to purge their own frames from stack traces
  // and evade detection. A non-native replacement is suspicious.
  try {
    const cst = (Error as unknown as Record<string, unknown>)['captureStackTrace']
    if (typeof cst === 'function' &&
        !Function.prototype.toString.call(cst).includes('[native code]')) {
      found.add('captureStackTrace-patched')
    }
  } catch { /* ignore */ }

  return [...found]
}

// Checks the integrity of native functions via 3 independent methods:
//
//   1. Native toString  — Function.prototype.toString.call(fn).includes('[native code]')
//      Limited: advanced stealth tools also patch Function.prototype.toString
//      to return '[native code]' for their own closures.
//
//   2. toString self-check  — calling toString on itself must produce
//      "function toString() { [native code] }". If stealth replaced toString,
//      it must handle this recursive case correctly — often impossible without an error.
//
//   3. Cross-realm iframe  — iframe.contentWindow.Function.prototype.toString
//      is in a pristine JS realm, not patched by stealth (which only operates on
//      the main window). Applied to main window getters, it exposes the truth
//      that the patched toString tries to hide.
function detectPatchedFunctions(): string[] {
  const patched: string[] = []

  // ── Targets to inspect (main window) ──────────────────────────────────────
  // Note: no expected string — each browser (Firefox, Chrome, Safari) formats
  // native functions differently (inline vs multiline [native code]). Exact
  // comparison would cause false positives on legitimate Firefox builds.
  const targets: Array<{ name: string; fn: unknown }> = [
    { name: 'webdriver getter',   fn: Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver')?.get },
    { name: 'permissions.query',  fn: navigator.permissions?.query },
    { name: 'isTrusted getter',   fn: Object.getOwnPropertyDescriptor(Event.prototype, 'isTrusted')?.get },
    { name: 'userAgent getter',   fn: Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent')?.get },
    // Additional targets: patched by scraping extensions (@grant none / unsafeWindow)
    // Detects TM/GM/VM scripts that intercept network requests from the page context.
    // Note: history.pushState intentionally excluded — too often patched by legitimate extensions
    // (analytics, SPA routers, history managers) → guaranteed false positives.
    { name: 'fetch',               fn: window.fetch },
    { name: 'XMLHttpRequest.open', fn: XMLHttpRequest.prototype.open },
  ]

  // ── Method 1: toString from the main window ────────────────────────────────
  // Vulnerable if stealth patches Function.prototype.toString itself.
  for (const { name, fn } of targets) {
    if (fn === undefined) continue
    try {
      const src = Function.prototype.toString.call(fn)
      if (!src.includes('[native code]')) patched.push(name)
    } catch {
      patched.push(name)  // toString threw → altered structure
    }
  }

  // ── Method 2: Function.prototype.toString self-check ──────────────────────
  // If stealth replaces toString, calling toString.call(toString) creates a recursive
  // problem that the tool rarely handles correctly.
  try {
    const fnTs = Function.prototype.toString
    const selfResult = fnTs.call(fnTs)
    // Expected result on any Chromium/Firefox/Safari browser:
    // "function toString() { [native code] }"
    if (!selfResult.includes('[native code]') || !selfResult.includes('toString')) {
      patched.push('Function.prototype.toString')
    }
  } catch {
    patched.push('Function.prototype.toString (threw)')
  }

  // ── Method 3: cross-realm toString via iframe ────────────────────────────
  // An iframe creates an independent JS realm. Its Function.prototype.toString
  // is not patched by stealth (which only operates on the main window).
  // Applying it to main window functions bypasses the stealth lie.
  try {
    const iframe = document.createElement('iframe')
    iframe.style.cssText = 'position:absolute;left:-9999px;width:0;height:0'
    document.body.appendChild(iframe)
    const xToString = (iframe.contentWindow as unknown as { Function?: typeof Function } | null)?.Function?.prototype?.toString
    document.body.removeChild(iframe)

    if (xToString) {
      for (const { name, fn } of targets) {
        if (fn === undefined) continue
        // Skip if already flagged by method 1 (avoid duplicates)
        if (patched.includes(name)) continue
        try {
          const src = xToString.call(fn)
          // Only check for [native code] marker — not exact string.
          // Firefox, Chrome, and Safari all produce different whitespace/newline
          // formatting around [native code], so exact comparison causes false
          // positives on legitimate Firefox builds.
          if (!src.includes('[native code]')) {
            patched.push(`${name} (cross-realm)`)
          }
        } catch {
          patched.push(`${name} (cross-realm threw)`)
        }
      }
    }
  } catch { /* ignore: iframe blocked by CSP or environment without DOM */ }

  // ── Structural integrity checks (not toString-based) ──────────────────────────
  // These detect pyppeteer_stealth / puppeteer-extra-plugin-stealth which inject
  // fake plugins as plain JS objects/arrays, not real browser API instances.
  // toString patches do NOT cover these — the prototype chain is checked directly.

  // Check 1 : navigator.plugins prototype
  // Real browser → PluginArray instance. Stealth → plain Array or Object.
  try {
    if (typeof PluginArray !== 'undefined' &&
        Object.getPrototypeOf(navigator.plugins) !== PluginArray.prototype) {
      patched.push('plugins-prototype')
    }
  } catch { /* ignore */ }

  // Check 2 : Plugin instanceof
  // Real browser → navigator.plugins[0] is a Plugin instance.
  // Stealth → plain object literal, instanceof Plugin = false.
  try {
    if (navigator.plugins.length > 0 &&
        typeof Plugin !== 'undefined' &&
        !(navigator.plugins[0] instanceof Plugin)) {
      patched.push('plugins-instanceof')
    }
  } catch { /* ignore */ }

  // Check 3 : mimeTypes / plugins coherence
  // Stealth fakes navigator.plugins (adds N entries) but does not touch navigator.mimeTypes,
  // which stays at 0 in headless Chrome. Real browsers always have at least 2 mimeTypes
  // (application/pdf + text/pdf). Note: do NOT compare counts directly — in real Chrome,
  // plugins.length (5) > mimeTypes.length (2), so that comparison causes false positives.
  try {
    if (navigator.plugins.length > 0 &&
        navigator.mimeTypes.length === 0) {
      patched.push('mimeTypes-incoherent')
    }
  } catch { /* ignore */ }

  // Check 4 : window.chrome internal APIs
  // Stealth creates a minimal window.chrome = { runtime: {} }.
  // Real Chrome has chrome.csi() and chrome.loadTimes() — internal APIs that
  // stealth rarely implements. Only fires when window.chrome exists (Chromium).
  try {
    const w = window as Window & { chrome?: { csi?: unknown; loadTimes?: unknown } }
    if (w.chrome !== undefined &&
        (typeof w.chrome.csi !== 'function' || typeof w.chrome.loadTimes !== 'function')) {
      patched.push('chrome-api-incomplete')
    }
  } catch { /* ignore */ }

  return [...new Set(patched)]  // deduplicate if method 1 + method 3 both found the same
}

export async function collectHeadlessSignals(): Promise<HeadlessInfo> {
  const [speechVoices, mediaDeviceCount] = await Promise.all([
    collectSpeechVoices(),
    collectMediaDevices(),
  ])
  return {
    speechVoices,
    mediaDeviceCount,
    patchedFunctions:     detectPatchedFunctions(),
    stackTraceArtifacts:  detectStackTraceArtifacts(),
  }
}

export function computeMouseStats(
  positions: { x: number; y: number }[],
): MouseStats {
  if (positions.length < 2) {
    return { moveCount: positions.length, avgVelocity: 0, maxVelocity: 0, straightLineRatio: -1 }
  }

  // Compute per-event velocities and total arc length
  let totalArc = 0
  const velocities: number[] = []
  for (let i = 1; i < positions.length; i++) {
    const dx = positions[i].x - positions[i - 1].x
    const dy = positions[i].y - positions[i - 1].y
    const d = Math.sqrt(dx * dx + dy * dy)
    velocities.push(d)
    totalArc += d
  }

  const sum = velocities.reduce((a, b) => a + b, 0)
  const avgVelocity = Math.round(sum / velocities.length)
  const maxVelocity = Math.round(Math.max(...velocities))

  // Straight-line ratio: direct distance between first and last point / total arc
  // 1.0 = perfectly straight (suspicious), lower = more human-like curve
  const first = positions[0]
  const last  = positions[positions.length - 1]
  const direct = Math.sqrt(
    (last.x - first.x) ** 2 + (last.y - first.y) ** 2,
  )
  const straightLineRatio = totalArc > 0 ? parseFloat((direct / totalArc).toFixed(3)) : -1

  return { moveCount: positions.length, avgVelocity, maxVelocity, straightLineRatio }
}
