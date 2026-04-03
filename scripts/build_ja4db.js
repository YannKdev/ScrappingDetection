// Filters ja4_database.json → GO_Interceptor/fingerprint/ja4db.json
// Keeps only verified entries with a JA4 fingerprint and an app/library label.
// Run: node scripts/build_ja4db.js

const fs = require('fs')
const path = require('path')

const srcPath  = path.resolve(__dirname, '../ja4_database.json')
const destPath = path.resolve(__dirname, '../GO_Interceptor/fingerprint/ja4db.json')

console.log('Reading source database…')
const data = JSON.parse(fs.readFileSync(srcPath, 'utf8'))

// Keep only verified entries that have a JA4 fingerprint AND an app or library label
const labeled = data.filter(
  e => e.ja4_fingerprint && e.verified && (e.application || e.library)
)

// Deduplicate by JA4: for each fingerprint, keep the entry with the richest data
const byJA4 = new Map()
labeled.forEach(e => {
  const existing = byJA4.get(e.ja4_fingerprint)
  if (!existing) { byJA4.set(e.ja4_fingerprint, e); return }
  // Prefer entry that has a User-Agent string
  if (!existing.user_agent_string && e.user_agent_string) {
    byJA4.set(e.ja4_fingerprint, e)
  }
})

const result = Array.from(byJA4.values()).map(e => ({
  ja4:              e.ja4_fingerprint,
  application:      e.application    || null,
  library:          e.library        || null,
  os:               e.os             || null,
  user_agent_string: e.user_agent_string || null,
  notes:            e.notes          || '',
}))

console.log(`Kept ${result.length} unique verified entries (from ${data.length} total)`)

fs.writeFileSync(destPath, JSON.stringify(result, null, 2))
console.log(`Written → ${destPath}`)

// Print summary
const appCounts = {}
result.forEach(e => {
  const key = e.application || ('lib:' + e.library)
  appCounts[key] = (appCounts[key] || 0) + 1
})
const sorted = Object.entries(appCounts).sort((a, b) => b[1] - a[1]).slice(0, 15)
console.log('\nTop entries by application:')
sorted.forEach(([k, v]) => console.log(`  ${String(v).padStart(3)}  ${k}`))
