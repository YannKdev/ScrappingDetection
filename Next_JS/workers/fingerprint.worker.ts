/// <reference lib="webworker" />
// Web Worker — runs off the main thread to avoid UI freezes.
// Has access to: OffscreenCanvas, OfflineAudioContext, crypto (SubtleCrypto).
// Does NOT have access to: document, window, DOM APIs.

export type WorkerRequest = { type: 'start' }

export type WorkerResponse =
  | { type: 'result'; canvasHash: string }
  | { type: 'error'; message: string }

self.onmessage = async (e: MessageEvent<WorkerRequest>) => {
  if (e.data.type !== 'start') return

  try {
    const canvasHash = await collectCanvas()
    ;(self as DedicatedWorkerGlobalScope).postMessage({
      type: 'result',
      canvasHash,
    } satisfies WorkerResponse)
  } catch (err) {
    ;(self as DedicatedWorkerGlobalScope).postMessage({
      type: 'error',
      message: String(err),
    } satisfies WorkerResponse)
  }
}

// ── Canvas fingerprint ──────────────────────────────────────────────────────
// Uses OffscreenCanvas (available in Workers).
// Different GPU drivers, font renderers, and OS produce slightly different pixel output,
// making this a reliable environment fingerprint.

async function collectCanvas(): Promise<string> {
  try {
    const canvas = new OffscreenCanvas(280, 60)
    const ctx = canvas.getContext('2d')
    if (!ctx) return 'unavailable'

    ctx.textBaseline = 'alphabetic'
    ctx.fillStyle = '#ff00ff'
    ctx.fillRect(0, 0, 10, 10)

    ctx.fillStyle = '#006699'
    ctx.font = '11px sans-serif'
    ctx.fillText('BotDetect fingerprint \u2691', 2, 16)

    ctx.fillStyle = 'rgba(102,204,0,0.7)'
    ctx.font = '18px monospace'
    ctx.fillText('BotDetect', 4, 50)

    // getImageData is synchronous — faster than convertToBlob
    const imageData = ctx.getImageData(0, 0, 280, 60)
    return djb2(imageData.data)
  } catch {
    return 'unavailable'
  }
}

// ── djb2 hash ───────────────────────────────────────────────────────────────
// Fast 32-bit hash suitable for fingerprint comparison (not cryptographic).

function djb2(data: Uint8ClampedArray): string {
  let hash = 5381
  // Sample every 4th byte (RGBA → every pixel's red channel) for speed
  for (let i = 0; i < data.length; i += 4) {
    hash = ((hash << 5) + hash) ^ data[i]
    hash = hash | 0 // keep 32-bit
  }
  return Math.abs(hash).toString(16).padStart(8, '0')
}
