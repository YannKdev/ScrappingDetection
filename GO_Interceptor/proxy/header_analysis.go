package proxy

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	tlsi "scrappingdetection/go-interceptor/tls"
)

// -----------------------------------------------------------------------
// BrowserInfo — detected client context
// -----------------------------------------------------------------------

// BrowserInfo holds all browser signals derived from User-Agent and Client Hints.
// Built once per request by detectBrowserInfo() and passed to all sub-checks.
type BrowserInfo struct {
	// Family is the rendering engine family: "chromium", "gecko", "webkit", "unknown".
	Family string

	// Brand is the specific browser product. Examples:
	//   Chromium family : "chrome", "brave", "edge", "opera", "vivaldi", "samsung", "webview", "headless"
	//   Gecko family    : "firefox"
	//   WebKit family   : "safari"
	//   iOS variants    : "chrome-ios", "firefox-ios", "edge-ios", "opera-ios"
	//   Unknown / bot   : "bot", "unknown"
	Brand string

	Mobile   bool   // mobile context (sec-ch-ua-mobile=?1, or UA contains Mobile/Android/iPhone)
	WebView  bool   // Android WebView embedded in an app — sec-fetch-* legitimately absent
	IOS      bool   // browser running on iOS — all iOS browsers are WebKit regardless of brand
	BotUA    bool   // UA matched a known scripted/headless/scraper pattern
	BotLabel string // e.g. "headless-chrome", "python-requests", "curl"
	BotScore int64  // pre-computed suspicious score for this bot pattern
}

// profileFamily returns the canonical profile key for header-order comparison.
// iOS browsers always compare against "safari" even if branded as Chrome/Edge.
func (b BrowserInfo) profileFamily() string {
	if b.IOS {
		return "safari"
	}
	switch b.Family {
	case "chromium":
		return "chrome"
	case "gecko":
		return "firefox"
	case "webkit":
		return "safari"
	default:
		return ""
	}
}

// orderThreshold is the Kendall tau distance below which header order is considered normal.
// More permissive for browsers that deliberately vary their fingerprints.
func (b BrowserInfo) orderThreshold() float64 {
	switch b.Brand {
	case "brave":
		return 0.30 // Privacy shields randomise some headers
	case "vivaldi", "samsung":
		return 0.25 // Minor Chromium-layer customisations
	case "safari":
		return 0.20 // Small iOS version differences
	default:
		return 0.15 // Chrome, Edge, Opera, Firefox — strict compliance
	}
}

// -----------------------------------------------------------------------
// HeaderAnalysis — aggregated result for a single request
// -----------------------------------------------------------------------

// HeaderAnalysis aggregates all header-level anomaly signals.
type HeaderAnalysis struct {
	BrowserBrand  string  // detected brand forwarded to backend as X-Browser-Brand
	UACoherence   string  // "ok" or mismatch description
	SecFetchValid string  // "ok" or pipe-separated violations
	PresenceNotes string  // pipe-separated reasons for presence score
	OrderProfile  string  // e.g. "brave-desktop", "safari-mobile", "unknown"
	OrderDistance float64 // Kendall tau [0, 1]; -1 if unavailable
	TotalScore    int64   // sum of all sub-scores applied to Redis

	// Per-check sub-scores (sum == TotalScore for non-bot requests).
	UAScore       int64 // UA ↔ sec-ch-ua coherence
	SecFetchScore int64 // Sec-Fetch-* value validity
	PresenceScore int64 // required header presence
	OrderScore    int64 // HTTP/2 header order vs canonical profile
}

// -----------------------------------------------------------------------
// Browser profiles — header names in wire order (lowercase)
// Pseudo-headers (:method etc.) appear only in HTTP/2 frames.
// Keyed by profile family: "chrome", "firefox", "safari".
// -----------------------------------------------------------------------

var desktopProfiles = map[string][]string{
	"chrome": {
		":method", ":authority", ":scheme", ":path",
		"sec-ch-ua", "sec-ch-ua-mobile", "user-agent", "sec-ch-ua-platform",
		"accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
		"referer", "accept-encoding", "accept-language", "cookie",
	},
	"firefox": {
		":method", ":path", ":authority", ":scheme",
		"user-agent", "accept", "accept-language", "accept-encoding",
		"referer", "connection", "cookie", "upgrade-insecure-requests",
		"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "priority",
	},
	"safari": {
		":method", ":scheme", ":authority", ":path",
		"host", "user-agent", "accept", "accept-language",
		"cookie", "referer", "accept-encoding", "priority",
	},
}

var mobileProfiles = map[string][]string{
	"chrome": {
		":method", ":authority", ":scheme", ":path",
		"sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
		"upgrade-insecure-requests", "user-agent", "accept",
		"sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest",
		"referer", "accept-encoding", "accept-language",
	},
	"safari": {
		":method", ":scheme", ":authority", ":path",
		"host", "user-agent", "accept", "accept-language",
		"cookie", "referer", "accept-encoding", "priority",
	},
	"firefox": {
		":method", ":path", ":authority", ":scheme",
		"user-agent", "accept", "accept-language", "accept-encoding",
		"referer", "connection", "cookie", "upgrade-insecure-requests",
		"sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "priority",
	},
}

// -----------------------------------------------------------------------
// Compiled regexps and bot UA patterns
// -----------------------------------------------------------------------

var (
	reChromeUA     = regexp.MustCompile(`Chrome/(\d+)`)
	reChromiumHint = regexp.MustCompile(`"Chromium";v="(\d+)"`)
	reChromeHint   = regexp.MustCompile(`"Google Chrome";v="(\d+)"`)
	reWebViewUA    = regexp.MustCompile(`Android.*\bwv\b`)
)

// botUAPatterns maps known scripted/bot UA substrings to a score and label.
// Ordered from most specific (highest score) to least specific.
var botUAPatterns = []struct {
	pattern string
	score   int64
	label   string
}{
	{"HeadlessChrome", 40, "headless-chrome"},
	{"Scrapy", 30, "scrapy"},
	{"python-requests", 30, "python-requests"},
	{"libwww-perl", 30, "libwww-perl"},
	{"curl/", 25, "curl"},
	{"wget/", 25, "wget"},
	{"Go-http-client/", 25, "go-http-client"},
	{"axios/", 20, "axios"},
	{"node-fetch", 20, "node-fetch"},
	{"undici", 15, "undici"},
}

// -----------------------------------------------------------------------
// detectBrowserInfo — single entry point for all browser detection
// -----------------------------------------------------------------------

// detectBrowserInfo parses User-Agent and Sec-Ch-Ua headers to build a BrowserInfo.
// Detection priority (highest → lowest):
//  1. iOS device  → always WebKit, even if brand is Chrome/Edge/Brave
//  2. Android WebView  → Chromium family, sec-fetch-* legitimately absent
//  3. Known bot UA  → immediate flag, fast path in analyzeHeaders
//  4. Sec-Ch-Ua brands  → most reliable brand detection (Chromium family only)
//  5. UA string fallback  → Firefox, Samsung, Opera, Edge, Safari, Chrome
func detectBrowserInfo(r *http.Request) BrowserInfo {
	ua := r.Header.Get("User-Agent")
	hint := r.Header.Get("Sec-Ch-Ua")
	mobileHint := r.Header.Get("Sec-Ch-Ua-Mobile")

	var bi BrowserInfo

	// Mobile context (checked early, used by all downstream logic).
	if mobileHint == "?1" ||
		strings.Contains(ua, "Mobile") ||
		strings.Contains(ua, "Android") ||
		strings.Contains(ua, "iPhone") ||
		strings.Contains(ua, "iPad") {
		bi.Mobile = true
	}

	// 1. iOS — all browsers on iOS are WebKit (Apple mandate).
	//    Chrome iOS = CriOS, Firefox iOS = FxiOS, Edge iOS = EdgiOS, Opera iOS = OPiOS.
	if strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad") {
		bi.IOS = true
		bi.Family = "webkit"
		bi.Mobile = true
		switch {
		case strings.Contains(ua, "CriOS"):
			bi.Brand = "chrome-ios"
		case strings.Contains(ua, "FxiOS"):
			bi.Brand = "firefox-ios"
		case strings.Contains(ua, "EdgiOS"):
			bi.Brand = "edge-ios"
		case strings.Contains(ua, "OPiOS"):
			bi.Brand = "opera-ios"
		default:
			bi.Brand = "safari"
		}
		return bi
	}

	// 2. Android WebView — identified by the "wv" token in UA.
	//    Apps embedding WebView produce Chromium-like UAs but omit Sec-Fetch-* and
	//    sec-ch-ua because those are browser (not WebView) features.
	if reWebViewUA.MatchString(ua) {
		bi.WebView = true
		bi.Family = "chromium"
		bi.Brand = "webview"
		bi.Mobile = true
		return bi
	}

	// 3. Known bot / scripted client patterns.
	for _, p := range botUAPatterns {
		if strings.Contains(ua, p.pattern) {
			bi.BotUA = true
			bi.BotLabel = p.label
			bi.BotScore = p.score
			if p.label == "headless-chrome" {
				bi.Brand = "headless"
				bi.Family = "chromium"
			} else {
				bi.Brand = "bot"
				bi.Family = "unknown"
			}
			return bi
		}
	}

	// 4. Sec-Ch-Ua brand list (Chromium family only — Firefox and Safari never send it).
	if hint != "" {
		bi.Family = "chromium"
		switch {
		case strings.Contains(hint, "Brave"):
			bi.Brand = "brave"
		case strings.Contains(hint, "Microsoft Edge"):
			bi.Brand = "edge"
		case strings.Contains(hint, "Opera"):
			bi.Brand = "opera"
		case strings.Contains(hint, "Vivaldi"):
			bi.Brand = "vivaldi"
		case strings.Contains(hint, "Samsung Internet"):
			bi.Brand = "samsung"
		default:
			// "Google Chrome" or just "Chromium" — treat as Chrome.
			bi.Brand = "chrome"
		}
		return bi
	}

	// 5. UA-string fallback — used when sec-ch-ua is absent.
	switch {
	case strings.Contains(ua, "SamsungBrowser"):
		bi.Brand = "samsung"
		bi.Family = "chromium"
	case strings.Contains(ua, "OPR/"):
		bi.Brand = "opera"
		bi.Family = "chromium"
	case strings.Contains(ua, "Edg/") || strings.Contains(ua, "Edge/"):
		bi.Brand = "edge"
		bi.Family = "chromium"
	case strings.Contains(ua, "Firefox"):
		bi.Brand = "firefox"
		bi.Family = "gecko"
	case strings.Contains(ua, "Safari") && !strings.Contains(ua, "Chrome"):
		bi.Brand = "safari"
		bi.Family = "webkit"
	case strings.Contains(ua, "Chrome"):
		bi.Brand = "chrome"
		bi.Family = "chromium"
	default:
		bi.Brand = "unknown"
		bi.Family = "unknown"
	}
	return bi
}

// -----------------------------------------------------------------------
// analyzeHeaders — main entry point called from fingerprintMiddleware
// -----------------------------------------------------------------------

func analyzeHeaders(r *http.Request, fp *tlsi.ConnectionFingerprint) HeaderAnalysis {
	bi := detectBrowserInfo(r)

	var a HeaderAnalysis
	a.BrowserBrand = bi.Brand

	// Fast path: known bot UA → skip all other checks, return immediately.
	if bi.BotUA {
		a.UACoherence = "bot-ua:" + bi.BotLabel
		a.SecFetchValid = "ok"
		a.PresenceNotes = "bot-ua"
		a.OrderProfile = "bot"
		a.OrderDistance = -1
		a.TotalScore = bi.BotScore
		return a
	}

	var score int64

	// 1. UA ↔ Sec-Ch-Ua coherence.
	uaScore, uaMsg := checkUACoherence(r, bi)
	score += uaScore
	a.UACoherence = uaMsg
	a.UAScore = uaScore

	// 2. Sec-Fetch-* value validation.
	sfScore, sfMsg := validateSecFetch(r)
	score += sfScore
	a.SecFetchValid = sfMsg
	a.SecFetchScore = sfScore

	// 3. Header presence scoring (context-aware).
	presScore, presNotes := scorePresence(r, bi)
	score += presScore
	a.PresenceNotes = presNotes
	a.PresenceScore = presScore

	// 4. Header order check (HTTP/2 only, brand-aware thresholds).
	orderScore, profile, dist := checkHeaderOrder(r, fp, bi)
	score += orderScore
	a.OrderProfile = profile
	a.OrderDistance = dist
	a.OrderScore = orderScore

	a.TotalScore = score
	return a
}

// -----------------------------------------------------------------------
// 1. UA ↔ Sec-Ch-Ua coherence
// -----------------------------------------------------------------------

func checkUACoherence(r *http.Request, bi BrowserInfo) (int64, string) {
	// iOS browsers never send sec-ch-ua — coherence checks don't apply.
	if bi.IOS {
		return 0, "ok"
	}
	// WebView: sec-ch-ua may be absent even though UA looks like Chrome.
	if bi.WebView {
		return 0, "ok"
	}

	ua := r.Header.Get("User-Agent")
	hint := r.Header.Get("Sec-Ch-Ua")
	mobile := r.Header.Get("Sec-Ch-Ua-Mobile")

	var score int64

	// Chrome ≥89 in UA but no sec-ch-ua (Client Hints era).
	if m := reChromeUA.FindStringSubmatch(ua); len(m) == 2 {
		chromeVer, _ := strconv.Atoi(m[1])
		if chromeVer >= 89 && hint == "" {
			score += 15
			return score, fmt.Sprintf("chrome-missing-hints:ua=%d", chromeVer)
		}
		// Both present — compare major versions.
		if hint != "" {
			hintVer := extractHintMajor(hint)
			if hintVer > 0 && abs(chromeVer-hintVer) > 2 {
				score += 20
				return score, fmt.Sprintf("chrome-version-mismatch:ua=%d,hint=%d", chromeVer, hintVer)
			}
		}
	}

	// sec-ch-ua present but UA claims Firefox or Safari (Chromium-only header).
	if hint != "" {
		if strings.Contains(ua, "Firefox") ||
			(strings.Contains(ua, "Safari") && !strings.Contains(ua, "Chrome")) {
			score += 20
			return score, "sec-ch-ua-on-non-chromium"
		}
	}

	// sec-ch-ua-mobile=?1 but UA has no mobile signals.
	if mobile == "?1" {
		if !strings.Contains(ua, "Mobile") &&
			!strings.Contains(ua, "Android") &&
			!strings.Contains(ua, "iPhone") {
			score += 10
			return score, "mobile-hint-desktop-ua"
		}
	}

	return 0, "ok"
}

func extractHintMajor(hint string) int {
	if m := reChromiumHint.FindStringSubmatch(hint); len(m) == 2 {
		v, _ := strconv.Atoi(m[1])
		return v
	}
	if m := reChromeHint.FindStringSubmatch(hint); len(m) == 2 {
		v, _ := strconv.Atoi(m[1])
		return v
	}
	return 0
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// -----------------------------------------------------------------------
// 2. Sec-Fetch-* value validation
// -----------------------------------------------------------------------

var secFetchSiteValues = map[string]bool{
	"same-origin": true, "same-site": true, "cross-site": true, "none": true,
}
var secFetchModeValues = map[string]bool{
	"navigate": true, "cors": true, "no-cors": true, "same-origin": true, "websocket": true,
}
var secFetchDestValues = map[string]bool{
	"document": true, "script": true, "style": true, "image": true, "font": true,
	"object": true, "embed": true, "worker": true, "serviceworker": true,
	"audio": true, "video": true, "manifest": true, "frame": true,
	"iframe": true, "report": true, "empty": true, "track": true, "xslt": true,
}

func validateSecFetch(r *http.Request) (int64, string) {
	var score int64
	var violations []string

	if v := r.Header.Get("Sec-Fetch-Site"); v != "" && !secFetchSiteValues[v] {
		score += 15
		violations = append(violations, "invalid-sec-fetch-site:"+v)
	}
	if v := r.Header.Get("Sec-Fetch-Mode"); v != "" && !secFetchModeValues[v] {
		score += 15
		violations = append(violations, "invalid-sec-fetch-mode:"+v)
	}
	if v := r.Header.Get("Sec-Fetch-Dest"); v != "" && !secFetchDestValues[v] {
		score += 10
		violations = append(violations, "invalid-sec-fetch-dest:"+v)
	}
	if v := r.Header.Get("Sec-Fetch-User"); v != "" && v != "?0" && v != "?1" {
		score += 5
		violations = append(violations, "invalid-sec-fetch-user:"+v)
	}

	if len(violations) == 0 {
		return 0, "ok"
	}
	return score, strings.Join(violations, "|")
}

// -----------------------------------------------------------------------
// 3. Header presence scoring (browser-context-aware)
// -----------------------------------------------------------------------

func scorePresence(r *http.Request, bi BrowserInfo) (int64, string) {
	var score int64
	var notes []string

	hasFetchSite := r.Header.Get("Sec-Fetch-Site") != ""
	hasFetchMode := r.Header.Get("Sec-Fetch-Mode") != ""
	hasFetchDest := r.Header.Get("Sec-Fetch-Dest") != ""
	hasAnySecFetch := hasFetchSite || hasFetchMode || hasFetchDest
	hasChHint := r.Header.Get("Sec-Ch-Ua") != ""

	if r.Header.Get("User-Agent") == "" {
		score += 25
		notes = append(notes, "no-user-agent")
	}
	if r.Header.Get("Accept") == "" {
		score += 10
		notes = append(notes, "no-accept")
	}
	if r.Header.Get("Accept-Language") == "" {
		score += 10
		notes = append(notes, "no-accept-language")
	}

	// WebView apps and iOS browsers legitimately omit Sec-Fetch-* headers.
	if !bi.WebView && !bi.IOS && !hasAnySecFetch {
		score += 20
		notes = append(notes, "no-sec-fetch")
	}

	// Chromium hint present but Sec-Fetch-* absent: contradiction.
	// Not applicable for WebView (Chromium-based but without browser-level Fetch API hooks).
	if hasChHint && !hasAnySecFetch && !bi.WebView {
		score += 15
		notes = append(notes, "hint-without-sec-fetch")
	}

	if len(notes) == 0 {
		return 0, "ok"
	}
	return score, strings.Join(notes, "|")
}

// -----------------------------------------------------------------------
// 4. Header order check (brand-aware thresholds)
// -----------------------------------------------------------------------

// checkHeaderOrder selects the profile family, waits up to 15 ms for HTTP/2
// header order to arrive, then computes the Kendall tau distance.
// The score threshold is adjusted per brand (e.g. Brave is more permissive).
func checkHeaderOrder(r *http.Request, fp *tlsi.ConnectionFingerprint, bi BrowserInfo) (int64, string, float64) {
	if fp == nil {
		return 0, "unknown", -1
	}

	// WebView order is unpredictable — skip rather than generate false positives.
	if bi.WebView {
		return 0, "webview", -1
	}

	// Wait for header order to be ready (populated by the H2SniffConn goroutine).
	select {
	case <-fp.HeaderOrderReady():
	case <-time.After(15 * time.Millisecond):
	}

	observed := fp.HeaderOrder
	if len(observed) == 0 {
		// HTTP/1.1, or H2 capture timed out.
		return 0, "unknown", -1
	}

	familyKey := bi.profileFamily()
	if familyKey == "" {
		return 0, "unknown", -1
	}

	var canonical []string
	if bi.Mobile {
		canonical = mobileProfiles[familyKey]
	} else {
		canonical = desktopProfiles[familyKey]
	}
	if len(canonical) == 0 {
		return 0, "unknown", -1
	}

	// Profile label uses the actual brand for clarity (e.g. "brave-desktop").
	context := "desktop"
	if bi.Mobile {
		context = "mobile"
	}
	profile := bi.Brand + "-" + context

	dist := kendallTauDistance(observed, canonical)
	threshold := bi.orderThreshold()

	var score int64
	switch {
	case dist < threshold:
		score = 0
	case dist < threshold+0.15:
		score = 5
	case dist < threshold+0.35:
		score = 15
	default:
		score = 25
	}

	return score, profile, dist
}

// -----------------------------------------------------------------------
// Kendall tau distance
// -----------------------------------------------------------------------

// kendallTauDistance returns the normalised Kendall tau distance in [0, 1]
// between observed and canonical, considering only headers present in both.
// 0 = identical relative order, 1 = fully reversed.
// Returns 0 if fewer than 2 common headers exist.
func kendallTauDistance(observed, canonical []string) float64 {
	// Build position map for the canonical profile.
	canonPos := make(map[string]int, len(canonical))
	for i, h := range canonical {
		canonPos[h] = i
	}

	// Filter observed to headers that also appear in the canonical profile.
	var filtered []string
	for _, h := range observed {
		if _, ok := canonPos[h]; ok {
			filtered = append(filtered, h)
		}
	}

	n := len(filtered)
	if n < 2 {
		return 0
	}

	// Map each filtered header to its canonical rank.
	perm := make([]int, n)
	for i, h := range filtered {
		perm[i] = canonPos[h]
	}

	// Count inversions: pairs (i, j) where i < j but perm[i] > perm[j].
	inversions := 0
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if perm[i] > perm[j] {
				inversions++
			}
		}
	}

	maxPairs := n * (n - 1) / 2
	return float64(inversions) / float64(maxPairs)
}
