# TrustShield AI — Python FastAPI Security Engine & Microservice

TrustShield AI is an intelligent platform for malicious website assessment, brand impersonation detection, scikit-learn phishing scoring, live TLS cryptographic auditing, and defensive header inspection.

---

## Architecture & Subsystems

The backend microservice is organized into clean, decoupled layers:

```
backend/
├── app/
│   ├── api/
│   │   └── v1/
│   │       ├── endpoints/
│   │       │   ├── scans.py        # POST /scans, GET /scans/{id}, GET /reports/{id}, GET /history
│   │       │   ├── health.py       # GET /health with subsystem matrix & SSRF status
│   │       │   └── router.py       # Aggregated v1 APIRouter
│   ├── core/
│   │   ├── config.py               # Pydantic v2 application settings & environment bindings
│   │   ├── errors.py               # Structured AppError hierarchy & exception handlers
│   │   ├── url_normalizer.py       # RFC 3986 URL canonicalization, Punycode/IDNA, domain extractor
│   │   └── scanner.py              # Asynchronous ScanEngine, ScanJob state machine, deduplication cache
│   ├── ml/
│   │   └── phish_lex.py            # Lexical tokenization, Shannon entropy, brand squat heuristics, ML model
│   ├── models/
│   │   └── schemas.py              # Pydantic v2 / stdlib dual-compatible request & response schemas
│   ├── security/
│   │   └── ssrf.py                 # Strict multi-layer SSRF validation & DNS pinning firewall
│   └── main.py                     # FastAPI application factory, CORS middleware, lifespan events
├── requirements.txt                # Production dependencies
└── README.md                       # Service deployment & operations manual
```

---

## Server-Side Request Forgery (SSRF) Defense Architecture

To protect private networks, internal cloud infrastructure, and adjacent tenant instances, TrustShield AI enforces multi-layered SSRF validation prior to any outbound network touch:

1. **Protocol Restriction**: Only `http:` and `https:` schemes are permitted. Schemes like `file:`, `ftp:`, `gopher:`, `ldap:`, `dict:`, `data:`, or `javascript:` are unconditionally rejected.
2. **Credential Stripping**: Any URL containing embedded authentication (`username:password@`) is rejected (`SSRF_CREDENTIALS_DISALLOWED`).
3. **Port Filtering**: Only standard web ports `80` and `443` are allowed. All alternative or administrative ports (`22`, `3306`, `5432`, `6379`, `8080`, `8443`, `9200`, etc.) are blocked.
4. **IP Subnet Denylist**:
   - Loopback (`127.0.0.0/8`, `::1`)
   - RFC 1918 Private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
   - Link-local and cloud metadata addresses (`169.254.0.0/16`, `fe80::/10`, `metadata.google.internal`)
   - Carrier-Grade NAT (`100.64.0.0/10`)
   - Broadcast and Multicast (`224.0.0.0/4`, `240.0.0.0/4`, `255.255.255.255/32`)
5. **DNS Resolution & IP Pinning**: Hostnames are resolved to IP addresses via `socket.getaddrinfo()`. All resolved addresses are verified against the denylist. The verified IP is pinned during network connections to prevent **DNS Rebinding (TOCTOU)** attacks.
6. **Passive-Only Outbound Ingestion**:
   - Outbound inspection uses `HEAD` requests only or strictly size-capped streaming reads (64 KB maximum).
   - Untrusted third-party HTML/JavaScript is never rendered or executed within the privileged API container.
   - Redirects are limited to at most 3 hops, with complete SSRF re-validation performed on each redirect destination.
   - Strict connection and read timeouts (3.5s per hop) prevent slowloris or socket starvation attacks.

---

## Local Development & Python Setup

### Prerequisites
- Python 3.10+
- virtualenv or venv

### Installation Steps

1. **Clone repository and navigate to backend directory**:
   ```bash
   cd backend
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Run the FastAPI server with Uvicorn**:
   ```bash
   uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

5. **Access Interactive API Documentation**:
   - Swagger UI: `http://localhost:8000/docs`
   - ReDoc: `http://localhost:8000/redoc`
   - Health Status: `http://localhost:8000/api/v1/health`

---

## Running the Automated Test Suite

The security and URL engine test suite runs directly via Python's standard `unittest` framework:

```bash
python3 -m unittest discover -s tests -v
```

### Covered Test Scenarios:
- `test_permit_only_http_and_https`: Rejects non-HTTP schemes (ftp, gopher, file).
- `test_reject_embedded_credentials`: Rejects URLs with embedded user/pass.
- `test_reject_localhost_and_internal_hostnames`: Rejects `localhost`, `.internal`, `.local`.
- `test_reject_private_and_reserved_ips`: Blocks 127.0.0.1, 10.x.x.x, 192.168.x.x, 169.254.169.254.
- `test_reject_unsafe_ports`: Blocks arbitrary ports (8080, 22, 6379, etc.).
- `test_malformed_urls`: Handles unparseable inputs gracefully with structured 400 errors.
- `test_canonicalize_equivalent_urls`: Normalizes uppercase schemes, default ports, query params.
- `test_domain_and_subdomain_extraction`: Extracts base domains and subdomains accurately.
- `test_scan_states_and_module_statuses`: Validates job state transitions and module timestamps.
- `test_duplicate_request_deduplication`: Verifies deduplication cache with 60-second TTL.
- `test_force_fresh_bypasses_cache`: Confirms `force_fresh=True` issues immediate re-scan.
- `test_partial_failure_resilience`: Ensures resilient fallback to `partial` status when an external probe fails.

---

## API Endpoints Reference

### 1. Submit Scan Job
- **`POST /api/v1/scans`**
- **Status**: `202 Accepted`
- **Request Body**:
  ```json
  {
    "url": "https://example.com/login",
    "force_fresh": false,
    "options": {
      "run_ml": true,
      "inspect_tls": true,
      "inspect_headers": true,
      "follow_redirects": true,
      "save_scan": true
    }
  }
  ```
- **Response**:
  ```json
  {
    "scan_id": "scan_a1b2c3d4e5f6",
    "request_id": "req_1741508000000_1234",
    "raw_url": "https://example.com/login",
    "canonical_url": "https://example.com/login",
    "domain": "example.com",
    "state": "queued",
    "progress_percent": 10,
    "module_statuses": {
      "lexical": { "status": "idle", "started_at": null, "completed_at": null, "error": null },
      "ml": { "status": "idle", "started_at": null, "completed_at": null, "error": null },
      "tls": { "status": "idle", "started_at": null, "completed_at": null, "error": null },
      "headers": { "status": "idle", "started_at": null, "completed_at": null, "error": null },
      "threat_intel": { "status": "idle", "started_at": null, "completed_at": null, "error": null }
    },
    "timestamps": {
      "queued_at": "2026-11-09T01:00:00.000Z",
      "started_at": null,
      "completed_at": null
    },
    "error": null,
    "result": null
  }
  ```

### 2. Poll Scan Status
- **`GET /api/v1/scans/{scan_id}`**
- Returns the current `ScanJobStateResponse` with module-level statuses (`idle`, `running`, `completed`, `partial`, `failed`).

### 3. Retrieve Forensic Report
- **`GET /api/v1/reports/{scan_id}`**
- **Status**: `200 OK` (when scan state is `completed` or `partial`)
- **Status**: `422 Unprocessable Entity` (if scan is still `queued`/`running`, with current progress percentage)
- Returns complete forensic report including risk score, ML feature importances, TLS socket audit, defensive headers, and actionable recommendations.

### 4. Paginated History
- **`GET /api/v1/history?limit=50&offset=0&verdict=phishing`**
- Returns `{ items: ScanJobStateResponse[], total: number, limit: number, offset: number }`.

### 5. Health Check
- **`GET /api/v1/health`**
- Returns subsystem health matrix, request ID, and active SSRF protection status.
