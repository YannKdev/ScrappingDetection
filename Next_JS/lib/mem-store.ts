// In-memory fallback store for browsers that block sessionStorage
// (iOS Safari private mode, some Android restricted browsers).
// Module-level variables persist across client-side Next.js navigations.

let _analysis: string | null = null
let _fpPayload: string | null = null

export const memStore = {
  getAnalysis:  ()          => _analysis,
  setAnalysis:  (v: string) => { _analysis  = v },
  getFpPayload: ()          => _fpPayload,
  setFpPayload: (v: string) => { _fpPayload = v },
  clear:        ()          => { _analysis = null; _fpPayload = null },
}
