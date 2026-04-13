'use client'

import { useEffect, useRef } from 'react'
import { useRouter } from 'next/navigation'
import {
  collectNavigator,
  collectScreen,
  collectWebGL,
  collectAudio,
  collectHeadlessSignals,
} from '@/lib/collect'
import type { FingerprintPayload } from '@/lib/types'
import type { WorkerResponse } from '@/workers/fingerprint.worker'
import { analyzeFingerprint } from './actions'
import { memStore } from '@/lib/mem-store'

export default function HomePage() {
  const router = useRouter()
  const honeypotRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    // Track isTrusted on any click during the challenge window
    // -1 = no click observed, 0 = all trusted, 1 = synthetic click detected
    let untrustedClick = -1
    const onAnyClick = (e: MouseEvent) => {
      if (!e.isTrusted) {
        untrustedClick = 1
      } else if (untrustedClick < 0) {
        untrustedClick = 0
      }
    }
    window.addEventListener('click', onAnyClick, { capture: true })

    async function runChallenge() {
      try {
        const [workerResult, audioHash, headless] = await Promise.all([
          runWorker(),
          collectAudio(),
          collectHeadlessSignals(),
        ])

        const navInfo    = collectNavigator()
        const screenInfo = collectScreen()
        const webgl      = collectWebGL()

        const payload: FingerprintPayload = {
          canvasHash:    workerResult.canvasHash,
          audioHash,
          webglVendor:   webgl.vendor,
          webglRenderer: webgl.renderer,
          navigatorInfo: navInfo,
          screenInfo,
          timezone:      Intl.DateTimeFormat().resolvedOptions().timeZone,
          // Mouse not measured during the initial challenge — sentinel moveCount:-1
          // avoids triggering mouse_moves/mouse_trajectory/click_delay
          mouse:         { moveCount: -1, avgVelocity: 0, maxVelocity: 0, straightLineRatio: -1 },
          timeToClickMs: 0,
          honeypot:      honeypotRef.current?.value ?? '',
          untrustedClick,
          headless,
        }

        const analysis    = await analyzeFingerprint(payload)
        const analysisStr = JSON.stringify(analysis)
        const payloadStr  = JSON.stringify(payload)

        // Always populate in-memory store (works on all browsers)
        memStore.setAnalysis(analysisStr)
        memStore.setFpPayload(payloadStr)

        // Best-effort: also persist to sessionStorage (blocked on some mobile browsers)
        try {
          sessionStorage.setItem('analysis',    analysisStr)
          sessionStorage.setItem('fp_payload',  payloadStr)
        } catch { /* sessionStorage unavailable — memStore is the fallback */ }
      } finally {
        router.push('/results?challenged=1')
      }
    }

    runChallenge()
    return () => window.removeEventListener('click', onAnyClick, { capture: true })
  }, [router])

  return (
    <main className="chargement" style={{ minHeight: '100vh', alignItems: 'center' }}>
      {/* Honeypot — invisible to real users, automatically filled by bots */}
      <input
        ref={honeypotRef}
        name="website"
        type="text"
        tabIndex={-1}
        aria-hidden="true"
        autoComplete="off"
        style={{ position: 'absolute', left: '-9999px', opacity: 0, height: 0 }}
      />

      <div className="text-center">
        <div className="spinner-border text-primary mb-3" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
        <p className="text-muted small text-uppercase letter-spacing-wide">Analyzing…</p>
      </div>
    </main>
  )
}

// ── Web Worker helper ──────────────────────────────────────────────────────────

function runWorker(): Promise<{ canvasHash: string }> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(
      new URL('../workers/fingerprint.worker.ts', import.meta.url),
    )
    worker.onmessage = (e: MessageEvent<WorkerResponse>) => {
      worker.terminate()
      if (e.data.type === 'result') {
        resolve({ canvasHash: e.data.canvasHash })
      } else {
        reject(new Error(e.data.message))
      }
    }
    worker.onerror = (e) => { worker.terminate(); reject(e) }
    worker.postMessage({ type: 'start' })
  })
}
