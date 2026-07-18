# Feature 5: IOC Enrichment (VirusTotal, AbuseIPDB, GeoIP) with Local Caching

## Overview

Let analysts enrich extracted IOCs against threat-intel sources — VirusTotal for hashes,
domains, and URLs; AbuseIPDB for IPs; offline GeoIP/ASN for IPs — and store results alongside
the IOC. Enrichment answers the first triage question for every indicator: "is this known-bad,
known-good, or unknown?" The app is local-first, so enrichment is **opt-in, per-explicit-action,
and clearly marked as leaving the machine**; results are cached locally so an indicator is
never queried twice unnecessarily.

## Current state

- IOC tables have a free-text `notes` column but no structured enrichment storage
  (`backend/utils/database.py`).
- `.env` / `.env.template` exists for configuration (`OLLAMA_HOST` pattern in
  `backend/routers/workflow.py:13-14`) — API keys follow the same pattern.
- No outbound HTTP client dependency yet (`httpx` comes with FastAPI's ecosystem; add explicitly).

## Design

- New `enrichments` table: `id`, `indicator_value (String(512), index)`,
  `indicator_kind` (ip | domain | url | hash), `provider` (virustotal | abuseipdb | geoip),
  `verdict` (malicious | suspicious | harmless | unknown), `score (Integer)` (VT detections or
  AbuseIPDB confidence), `raw_json (Text)`, `fetched_at (DateTime)`.
  Keyed by indicator value (not IOC row) so results are shared across cases — this also gives
  cross-case "seen before in VT" for free.
- Cache policy: serve from cache if `fetched_at` < 7 days old; `force=true` refreshes.
- Providers behind a small interface (`EnrichmentProvider.supports(kind)`, `.lookup(value)`)
  so new sources (OTX, Shodan) are additive.
- **Privacy guard:** if no API key is configured, the provider is listed as unavailable; the UI
  shows a one-time confirmation ("This sends the indicator to VirusTotal") before the first
  external lookup in a session. Hash lookups send only the hash. URL lookups warn explicitly
  (URLs may contain victim data).
- Rate limiting: simple token bucket per provider (VT free tier = 4 req/min) with queued
  sequential lookups for "Enrich all".

## Implementation tasks

### Backend

- [ ] `uv add httpx`; add `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `GEOIP_DB_PATH` to
      `.env.template`.
- [ ] `Enrichment` model + helpers (`get_cached`, `save_enrichment`) in
      `backend/utils/database.py`.
- [ ] New module `backend/utils/enrichment/` package:
      - `base.py` — provider interface + registry + token-bucket rate limiter.
      - `virustotal.py` — v3 API: `/files/{hash}`, `/domains/{domain}`, `/urls/{id}`; verdict
        from `last_analysis_stats` (malicious>0 → malicious, suspicious>0 → suspicious, else
        harmless); score = malicious count.
      - `abuseipdb.py` — `/api/v2/check`; verdict from `abuseConfidenceScore`
        (≥75 malicious, ≥25 suspicious, else harmless).
      - `geoip.py` — optional local MaxMind GeoLite2 via `geoip2` if `GEOIP_DB_PATH` set;
        country/ASN only, verdict always `unknown` (informational).
- [ ] New router `backend/routers/enrichment.py`:
      - `GET  /enrichment/providers` → which providers are configured/available.
      - `POST /enrichment/lookup` body `{indicator, kind, provider?, force?}` → runs matching
        providers, returns stored enrichment rows (cache-first).
      - `POST /cases/{case_id}/enrich` → queue lookups for every enrichable IOC in the case;
        returns per-indicator results (or job-based if plan 2 is in — reuse the job manager).
      - `GET /cases/{case_id}/enrichments` → all cached enrichments joined to the case's IOCs.
- [ ] Timeouts (10 s), graceful degradation: provider errors recorded as `verdict=unknown`
      with the error in `raw_json`, never a 500 for the whole batch.

### Frontend

- [ ] Verdict badges in `frontend/components/ioc-tables.tsx`: red "Malicious (54/70)", amber
      "Suspicious", green "Clean", grey "Unknown", none if never enriched. Tooltip shows
      provider + fetched_at.
- [ ] Per-row "Enrich" action and a case-level "Enrich all" button with progress
      ("12/40 indicators…") and the privacy confirmation dialog.
- [ ] Detail popover on badge click: per-provider breakdown, link out to VT/AbuseIPDB web UI,
      "Refresh" (force) button.
- [ ] Provider availability surfaced in a small settings/status area (grey out buttons with a
      "configure VIRUSTOTAL_API_KEY" hint when missing).

## Testing

- [ ] `tests/test_enrichment.py` — all provider HTTP calls mocked (httpx `MockTransport`):
      - Verdict mapping tables for VT stats and AbuseIPDB scores (parametrized).
      - Cache: second lookup within TTL performs zero HTTP calls; `force=true` performs one.
      - Provider error → `unknown` verdict stored, batch continues.
      - No API key → provider reported unavailable, lookup returns clear 400, no outbound call.
      - Rate limiter: N queued lookups never exceed the per-minute budget (use a fake clock).
      - `POST /cases/{id}/enrich` enriches only enrichable types (skips registry keys etc.).
- [ ] Manual test with a real VT key against EICAR hash
      (`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe1a2c4538aabf651fd0f`) → malicious verdict.

## Success criteria

1. With keys configured, an analyst gets a verdict badge on any hash/IP/domain/URL in ≤ 2 clicks.
2. No network request ever leaves the machine without an explicit enrich action + first-time
   confirmation; with no keys configured the app behaves exactly as today.
3. Repeated lookups of the same indicator hit the local cache (verified by tests) and enrichment
   of a 50-IOC case respects provider rate limits without failing.
4. Enrichment results persist across restarts and are visible from every case sharing the indicator.
5. All tests pass offline (mocked transports) — CI needs no API keys.
