package fingerprint

import (
	_ "embed"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
)

//go:embed ja4db.json
var ja4dbRaw []byte

// JA4DBEntry is one record from the FoxIO JA4 fingerprint database.
type JA4DBEntry struct {
	JA4             string `json:"ja4"`
	Application     string `json:"application"`
	Library         string `json:"library"`
	OS              string `json:"os"`
	UserAgentString string `json:"user_agent_string"`
	Notes           string `json:"notes"`
}

// DisplayName returns the trimmed application or library name.
func (e *JA4DBEntry) DisplayName() string {
	if e.Application != "" {
		return strings.TrimSpace(e.Application)
	}
	return strings.TrimSpace(e.Library)
}

// IsLegitBrowser returns true if the entry is a known real browser.
func (e *JA4DBEntry) IsLegitBrowser() bool {
	name := strings.ToLower(e.DisplayName())
	for _, b := range []string{"chrome", "firefox", "safari", "edge", "opera", "chromium"} {
		if strings.Contains(name, b) {
			return true
		}
	}
	return false
}

// IsThreat returns true if the entry is known malware or offensive tooling.
func (e *JA4DBEntry) IsThreat() bool {
	name := strings.ToLower(e.DisplayName())
	for _, t := range []string{
		"cobalt strike", "icedid", "pikabot", "qakbot", "lumma",
		"sliver", "metasploit", "beacon", "malware", "c2",
	} {
		if strings.Contains(name, t) {
			return true
		}
	}
	return false
}

// IsScriptLib returns true if the entry is a known HTTP scripting library.
func (e *JA4DBEntry) IsScriptLib() bool {
	name := strings.ToLower(e.DisplayName())
	for _, l := range []string{"python", "golang", "curl", "wget", "java", "ruby", "node", "go "} {
		if strings.Contains(name, l) {
			return true
		}
	}
	return false
}

// ── Singleton lookup map ──────────────────────────────────────────────────────

var (
	ja4db     map[string]*JA4DBEntry
	ja4dbOnce sync.Once
)

func loadJA4DB() {
	var entries []JA4DBEntry
	if err := json.Unmarshal(ja4dbRaw, &entries); err != nil {
		ja4db = make(map[string]*JA4DBEntry)
		return
	}
	ja4db = make(map[string]*JA4DBEntry, len(entries))
	for i := range entries {
		e := &entries[i]
		if e.JA4 != "" {
			ja4db[e.JA4] = e
		}
	}
}

// LookupJA4 returns the DB entry for a JA4 fingerprint, or nil if unknown.
func LookupJA4(ja4 string) *JA4DBEntry {
	ja4dbOnce.Do(loadJA4DB)
	return ja4db[ja4]
}

// partBFamilies maps known cipher-suite hashes (JA4 Part B) to browser families.
// Part B = SHA256[:12] of the sorted, de-GREASE'd cipher suite list.
// This hash is much more stable across browser versions than Part C (extension list),
// making it a reliable fallback when the exact JA4 is not in the database.
var partBFamilies = map[string]string{
	// Chromium-based (Chrome, Edge ≥88, Brave, Opera): cipher set stable since Chrome 72.
	"8daaf6152771": "Chromium",
	// Firefox: cipher set stable from Firefox 84 to 148+.
	"5b57614c22b0": "Firefox",
	"95e1cefdbe28": "Firefox",
	// Safari (macOS/iOS): distinct cipher set.
	"24fc43eb1c96": "Safari",
	// Legacy Edge (EdgeHTML, pre-Chromium).
	"e72c3b3287f1": "Edge (legacy)",
	"4b22cbed5bed": "Edge (legacy)",
}

// LookupJA4Fuzzy first tries an exact DB match, then falls back to Part-B
// family detection when the exact fingerprint (Part C) is not in the database.
// Returns (exact entry or nil, fuzzy display name or "").
func LookupJA4Fuzzy(ja4 string) (*JA4DBEntry, string) {
	l1, l2, _ := LookupJA4All(ja4)
	if l1 != nil {
		return l1, ""
	}
	return nil, l2
}

// LookupJA4All returns predictions at all three levels:
//
//   - l1: exact DB entry (Level 1 — full JA4 match)
//   - l2: Part-B family name (Level 2 — cipher-suite hash)
//   - l3: Part-A structural guess (Level 3 — TLS structure heuristic)
func LookupJA4All(ja4 string) (l1 *JA4DBEntry, l2 string, l3 string) {
	ja4dbOnce.Do(loadJA4DB)
	l1 = ja4db[ja4]
	parts := strings.SplitN(ja4, "_", 3)
	if len(parts) == 3 {
		if family, ok := partBFamilies[parts[1]]; ok {
			l2 = family + " (heuristic)"
		}
	}
	l3 = guessFromPartA(ja4)
	return
}

// guessFromPartA infers a coarse browser/tool family from JA4 Part A structure.
// JA4 Part A: {transport}{version}{sni}{ciphers:02}{exts:02}{alpn}
// Example: t13d1516h2 → TLS 1.3, domain SNI, 15 ciphers, 16 exts, h2
func guessFromPartA(ja4 string) string {
	us := strings.Index(ja4, "_")
	if us < 10 {
		return ""
	}
	a := ja4[:us]
	if len(a) < 10 {
		return ""
	}
	// a[0]   = transport ('t'=TCP, 'q'=QUIC)
	// a[1:3] = TLS version string ("13", "12", ...)
	// a[3]   = SNI ('d'=domain, 'i'=IP)
	// a[4:6] = cipher suite count (zero-padded 2 digits)
	// a[6:8] = extension count (zero-padded 2 digits)
	// a[8:10]= ALPN first-two ("h2", "h1", "00"=none)
	version := a[1:3]
	ciphers, err1 := strconv.Atoi(a[4:6])
	exts, err2 := strconv.Atoi(a[6:8])
	alpn := a[8:10]
	if err1 != nil || err2 != nil {
		return ""
	}

	// TLS 1.2 max: modern browsers all mandate TLS 1.3 since 2020.
	if version == "12" {
		return "Library/tool (TLS 1.2)"
	}
	// No ALPN: bare TLS stack without protocol negotiation (scanner, minimal curl).
	if alpn == "00" {
		return "Scanner/tool (no ALPN)"
	}
	// Very few cipher suites: script libraries (Python-requests 3, curl 4-6).
	if ciphers < 10 {
		return "Script library (few ciphers)"
	}
	// Very few extensions: simplistic TLS stack (libraries omit SNI, session-ticket, etc.).
	if exts < 8 {
		return "Script library (few extensions)"
	}
	// Safari: historically ships 19-21 cipher suites (distinct from Chromium/Firefox).
	if version == "13" && ciphers >= 19 {
		return "Safari (heuristic — TLS structure)"
	}
	// Modern browser profile: TLS 1.3, negotiated ALPN, ≥14 ciphers, ≥10 exts.
	// Chrome ~15 ciphers/16 exts, Firefox ~17 ciphers/14 exts — overlap too large to
	// distinguish at this level; L2 (Part B) handles that when the hash is known.
	if version == "13" && ciphers >= 14 && exts >= 10 {
		return "Chromium/Firefox (heuristic — TLS structure)"
	}
	return "Modern HTTP client (heuristic)"
}
