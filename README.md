# Bot Detection Engine

Bot and scraper detection in three layers: TLS network fingerprinting (Go), JavaScript signals (Next.js), session correlation (Redis).
Note: this is not a complete tool (IP reputation, JA4 fingerprint redundancy, large-scale data analysis, behavioral model)

---

## Architecture

```text
Client
  │ HTTPS
  ▼
Proxy Go :8443       — TLS/JA4, analyse headers, session Redis
  │ HTTP + X-headers
  ▼
Next.js :3000        — scoring JS + comportement
  │
  ▼
Redis :6379          — mémoire inter-requêtes
```

---

## Browser Results

| Outil / Navigateur | Score | Verdict |
| --- | --- | --- |
| Firefox Windows 148 | 0 | ✅ |
| Chrome Windows 145 | 0 | ✅ |
| Edge Windows 145 | 0 | ✅ |
| Brave Windows 145 | 0 | ✅ |
| Chrome Android 145 | 0 | ✅ |
| Firefox Android 148 | 0 | ✅ |
| Brave Android 145 | 0 | ✅ |
| Samsung Internet Android 29 | 0 | ✅ |

## Tool Results

Tests performed on a legitimate machine (Windows PC). When running these tools on servers, expect better detection results.

| Navigateur | Score | Verdict |
| --- | --- | --- |
| Puppeteer | 75 | ✅ |
| Puppeteer-extra-stealth | 75 | ✅ |
| Playwright | 70 | ✅ |
| Playwright-stealth | 110 | ✅ |
| Selenium-stealth | 110 | ✅ |
| Electron | 90 | ✅ |
| UndetectedChromeBrowser | 40 | ⚠️ (ToDo) |
| nodriver | 10 | ❌ (ToDo) |
| Pyppeteer-stealth | 0 | ❌ (ToDo) |

---

## How It Works

**Go Proxy** — executed before any HTTP byte

1. TLS ClientHello parsing → JA4 fingerprint (FoxIO spec, SHA-256)
2. JA4 database lookup (61 entries): threat / tool / browser, 3 confidence levels
3. HTTP/2: capture SETTINGS frames + HPACK header order
4. Header analysis: UA ↔ sec-ch-ua consistency, sec-fetch-* validation, presence score, Kendall τ distance
5. Redis session: score init (new client) or TLS change detection (known client)

**Next.js** — Scoring signals list

| Groupe | Signal | Score |
| --- | --- | --- |
| TLS | Known threat in JA4 database | +90 |
| TLS | Known lib/tool in JA4 database | +35 |
| TLS | JA4 database ≠ User-Agent | +40 |
| TLS coherence | GREASE + Firefox UA | +70 |
| TLS coherence | FFDHE missing + Firefox UA ≥76 | +50 |
| TLS coherence | FFDHE present + Chrome UA | +60 |
| TLS coherence | No PQ group + Chrome UA ≥130 | +45 |
| JS | navigator.webdriver | +40 |
| JS | Selenium / Playwright / Puppeteer globals | +50 |
| JS | Virtual WebGL renderer | +25 |
| Headless | Empty speechSynthesis | +30 |
| Headless | Patched native functions | +45 |
| Headless | CDP / extension stack trace | +60 |
| Behavior | Honeypot filled | +100 |
| Behavior | Synthetic click | +60 |
| Behavior | No mouse movement | +20 |

Score final = Σ signaux + min(30, score Redis)

JS-free version for testing with a simple GET request (network layer analysis, JSON response).
No JS: `GET /api/verify` — TLS + headers only.

**Verdict**
Rough score to get a general idea.

| Score | Verdict |
| --- | --- |
| 0 – 24 | ✅ human |
| 25 – 59 | ⚠️ suspect |
| ≥ 60 | ❌ bot |

---

## Getting Started

```bash
redis-server

cd GO_Interceptor/ && UPSTREAM_URL=http://localhost:3000 go run .

cd Next_JS/ && npm install && npm run dev
```

Go variables: `UPSTREAM_URL` (required), `LISTEN_ADDR` (default `:8443`), `TLS_CERT`/`TLS_KEY` (auto-generated if missing), `REDIS_URL`.

---

## To Do

- Test on a wider range of browsers / versions / mobile devices
- Test more webdrivers available on the market
- Improve stack trace artifact detection (currently simplistic)
