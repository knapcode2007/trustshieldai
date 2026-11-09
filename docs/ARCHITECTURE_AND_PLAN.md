# TrustShield AI — System Architecture & Implementation Plan
**Document Version:** 1.0.0  
**Target Milestone:** Foundation Phase  
**Author:** TrustShield Architecture & Cybersecurity Research Team

---

## 1. Executive Summary & Problem Domain
Modern cyber threats leverage polymorphic phishing campaigns, evasive redirect chains, fraudulent domain squatting, and compromised TLS certificates to deceive end users and bypass static firewalls. **TrustShield AI** is an intelligent security orchestration and detection platform that unites:
1. **Multi-layer Phishing Detection**: Feature extraction (lexical, domain entropy, obfuscation, spoofing keywords) coupled with scikit-learn predictive classifiers.
2. **Deep Malicious Website Assessment**: Live HTTP header inspection, heuristic credential harvest detection, iframe/script evasion analysis.
3. **TLS Certificate Deep Validation**: Cryptographic cipher evaluation, certificate chain integrity, revocation check hints, SAN audits, expiration countdowns.
4. **Collaborative Threat Intelligence (CTI)**: Supabase PostgreSQL-backed Indicators of Compromise (IOC) registry with community verification, severity scoring, and export capabilities.

---

## 2. System Architecture Diagram

```
+---------------------------------------------------------------------------------------+
|                                    TRUSTSHIELD AI                                     |
+---------------------------------------------------------------------------------------+
|                                                                                       |
|   +-------------------------------------------------------------------------------+   |
|   |                       Frontend Layer (React 19 + Vite)                        |   |
|   |  - Responsive SOC Application Shell (Header, Navigation, Quick Scan, Alerts)  |   |
|   |  - shadcn/ui Component Library + Tailwind CSS v4 Dark Security Theme          |   |
|   |  - Resilient Typed API Client with Exponential Backoff & Graceful Error State |   |
|   |  - Supabase Auth & Session Synchronization (Client SDK)                       |   |
|   +-------------------------------------------------------------------------------+   |
|                                         |                                             |
|                                         | HTTPS / JSON API v1                         |
|                                         v                                             |
|   +-------------------------------------------------------------------------------+   |
|   |           Hybrid Application Gateway & Full-Stack Controller (Port 3000)      |   |
|   |  - Node.js / Express Server (server.ts) mounting Vite Middleware in Dev       |   |
|   |  - Native API Route Gateway (/api/v1/*)                                       |   |
|   |  - Upstream Reverse Proxy to FastAPI Microservice (http://127.0.0.1:8000)     |   |
|   |  - Built-in System Telemetry, Health Probes & Environment Introspection       |   |
|   +-------------------------------------------------------------------------------+   |
|                                         |                                             |
|                                         | Reverse Proxy / Internal RPC                |
|                                         v                                             |
|   +-------------------------------------------------------------------------------+   |
|   |                     Python Backend (FastAPI Microservice)                     |   |
|   |  - FastAPI ASGI Engine (Uvicorn / backend/app/main.py)                        |   |
|   |  - Pydantic v2 Contract Validation & Unified Error Handling Architecture      |   |
|   |  - /api/v1/health (Multi-subsystem health, ML status, DB connectivity)        |   |
|   |  - /api/v1/scan (URL feature extraction & ML classifier interface)            |   |
|   |  - /api/v1/tls (SSL/TLS socket handshake & x509 cert parser)                  |   |
|   |  - /api/v1/intel (Threat intelligence repository queries)                     |   |
|   +-------------------------------------------------------------------------------+   |
|               |                                                   |                   |
|               v                                                   v                   |
|   +-------------------------+                     +-------------------------------+   |
|   | ML Engine (scikit-learn)|                     | Persistence (Supabase / PG)   |   |
|   | - Lexical Feature Extr. |                     | - scans (Audit history)       |   |
|   | - Domain Entropy Calc   |                     | - threat_indicators (IOCs)    |   |
|   | - RandomForest / LinReg |                     | - tls_audits (Cert history)   |   |
|   | - Probability Scoring   |                     | - RLS & Secure Policies       |   |
|   +-------------------------+                     +-------------------------------+   |
|                                                                                       |
+---------------------------------------------------------------------------------------+
```

---

## 3. Directory Structure

```
├── .env.example                          # Canonical environment configuration blueprint
├── index.html                            # Application entry with SEO and Security meta tags
├── metadata.json                         # Project metadata and AI Studio capabilities
├── package.json                          # Node.js dependencies & scripts
├── server.ts                             # Full-Stack Express gateway + Vite dev middleware
├── tsconfig.json                         # TypeScript configuration
├── vite.config.ts                        # Vite configuration with Tailwind CSS v4 plugin
│
├── backend/                              # Python FastAPI Microservice
│   ├── requirements.txt                  # Python dependency list
│   └── app/
│       ├── __init__.py
│       ├── main.py                       # FastAPI entrypoint, middleware, error handlers
│       ├── core/
│       │   ├── __init__.py
│       │   ├── config.py                 # Pydantic v2 application settings
│       │   └── errors.py                 # Unified error schema and custom exception handlers
│       ├── models/
│       │   ├── __init__.py
│       │   └── schemas.py                # Pydantic models for Health, Scans, TLS, Intel
│       ├── api/
│       │   ├── __init__.py
│       │   └── v1/
│       │       ├── __init__.py
│       │       ├── router.py             # Main v1 API router aggregation
│       │       └── endpoints/
│       │           ├── __init__.py
│       │           ├── health.py         # Subsystem health verification endpoint
│       │           ├── scan.py           # Phishing & URL scan foundation endpoint
│       │           ├── tls.py            # TLS certificate validation foundation endpoint
│       │           └── intel.py          # Threat intelligence foundation endpoint
│       ├── ml/
│       │   ├── __init__.py
│       │   └── pipeline.py               # Feature extractor and model interface
│       ├── security/
│       │   ├── __init__.py
│       │   ├── heuristics.py             # High-speed regex and lexical heuristics
│       │   └── tls_inspector.py          # Python socket/ssl cert parser
│       └── db/
│           ├── __init__.py
│           └── supabase.py               # Supabase Python client integration
│
├── docs/                                 # Documentation & Architecture
│   └── ARCHITECTURE_AND_PLAN.md          # Implementation plan & contracts (this document)
│
└── src/                                  # React 19 Frontend Application
    ├── main.tsx                          # React DOM mount point
    ├── index.css                         # Global styles & shadcn CSS theme variables
    ├── App.tsx                           # Application controller & view switcher
    ├── lib/
    │   └── utils.ts                      # shadcn clsx + twMerge utility
    ├── services/
    │   ├── apiClient.ts                  # Typed HTTP client with error handling & retries
    │   ├── supabaseClient.ts             # Supabase JS client with env fallback
    │   └── types.ts                      # Complete TypeScript contracts matching Pydantic schemas
    ├── hooks/
    │   ├── useSystemHealth.ts            # Reactive hook for subsystem health monitoring
    │   └── useNotifications.ts           # Alert notification state hook
    └── components/
        ├── ui/                           # shadcn/ui primitives
        │   ├── alert.tsx
        │   ├── badge.tsx
        │   ├── button.tsx
        │   ├── card.tsx
        │   ├── dialog.tsx
        │   ├── input.tsx
        │   └── tabs.tsx
        ├── layout/
        │   ├── AppShell.tsx              # Master layout with navbar, sidebar, footer
        │   ├── Header.tsx                # Security console topbar with quick search & status
        │   ├── Sidebar.tsx               # Navigation drawer with active route indicators
        │   └── StatusBanner.tsx          # Real-time health & environment connectivity banner
        └── views/
            ├── DashboardView.tsx         # Security operations overview & recent signals
            ├── ScanView.tsx              # URL & Phishing analysis console
            ├── TlsView.tsx               # TLS/SSL Certificate Inspector
            ├── ThreatIntelView.tsx       # Collaborative Threat Intelligence repository
            └── SystemHealthView.tsx      # Multi-service telemetry & diagnostics
```

---

## 4. API Contracts (FastAPI & Gateway Specification)

### 4.1 Common Error Envelope
All error responses adhere to RFC 7807 problem details pattern:
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR | RESOURCE_NOT_FOUND | UPSTREAM_FAILURE | SERVICE_UNAVAILABLE",
    "message": "Human-readable error explanation",
    "details": { "field": "url", "issue": "Invalid URL scheme" }
  },
  "timestamp": "2026-11-09T08:30:00Z"
}
```

### 4.2 Endpoint: `GET /api/v1/health`
Checks health of the API server, database connectivity, and ML pipeline readiness.
- **Response `200 OK`**:
```json
{
  "status": "healthy",
  "app_name": "TrustShield AI",
  "version": "1.0.0",
  "environment": "development",
  "timestamp": "2026-11-09T08:30:00Z",
  "subsystems": {
    "api_gateway": { "status": "online", "latency_ms": 1.2 },
    "fastapi_service": { "status": "online", "version": "0.115.0" },
    "ml_engine": { "status": "ready", "model_version": "phish-rf-v1.0" },
    "database": { "status": "configured", "provider": "supabase" },
    "tls_analyzer": { "status": "ready" }
  }
}
```

### 4.3 Endpoint: `POST /api/v1/scan`
Submits a URL for comprehensive security analysis.
- **Request Body**:
```json
{
  "url": "https://secure-login.verification-bank.com/auth",
  "options": {
    "run_ml": true,
    "inspect_tls": true,
    "follow_redirects": true,
    "save_scan": true
  }
}
```
- **Response `200 OK`**:
```json
{
  "scan_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "url": "https://secure-login.verification-bank.com/auth",
  "normalized_url": "https://secure-login.verification-bank.com/auth",
  "domain": "verification-bank.com",
  "verdict": "phishing",
  "risk_score": 88,
  "confidence": 0.94,
  "heuristics": {
    "suspicious_keywords": ["secure-login", "verification"],
    "has_ip_in_url": false,
    "subdomain_count": 2,
    "url_entropy": 4.12
  },
  "ml_prediction": {
    "model": "RandomForest-PhishLex-v1",
    "probability_phish": 0.942,
    "key_influencing_features": ["subdomain_depth", "target_brand_token_distance"]
  },
  "tls_summary": {
    "valid": true,
    "issuer": "Let's Encrypt",
    "days_remaining": 45
  },
  "created_at": "2026-11-09T08:30:00Z"
}
```

### 4.4 Endpoint: `POST /api/v1/tls/inspect`
Dedicated TLS certificate probe.
- **Request Body**:
```json
{
  "hostname": "example.com",
  "port": 443
}
```

### 4.5 Endpoint: `GET /api/v1/intel/indicators`
Retrieve verified and community-reported threat indicators.
- **Query Parameters**: `type=url&limit=20&severity=high`

---

## 5. Supabase PostgreSQL Database Schema

```sql
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Scans Table: Primary audit trail of all inspected targets
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    target_url TEXT NOT NULL,
    domain TEXT NOT NULL,
    normalized_url TEXT NOT NULL,
    scan_type VARCHAR(32) NOT NULL DEFAULT 'url_phishing',
    verdict VARCHAR(32) NOT NULL CHECK (verdict IN ('clean', 'suspicious', 'phishing', 'malicious')),
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    ml_confidence NUMERIC(4, 3) NOT NULL DEFAULT 0.000,
    heuristics JSONB NOT NULL DEFAULT '{}'::jsonb,
    ml_features JSONB NOT NULL DEFAULT '{}'::jsonb,
    tls_summary JSONB DEFAULT NULL,
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for domain analysis and user history
CREATE INDEX IF NOT EXISTS idx_scans_domain ON public.scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON public.scans(verdict);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON public.scans(scanned_at DESC);

-- 2. Threat Indicators Table (IOCs): Collaborative Threat Intelligence
CREATE TABLE IF NOT EXISTS public.threat_indicators (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    indicator_value TEXT NOT NULL UNIQUE,
    indicator_type VARCHAR(32) NOT NULL CHECK (indicator_type IN ('url', 'domain', 'ip', 'sha256')),
    threat_category VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    confidence INTEGER NOT NULL CHECK (confidence >= 0 AND confidence <= 100),
    source VARCHAR(64) NOT NULL DEFAULT 'trustshield_community',
    reported_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    tags TEXT[] NOT NULL DEFAULT '{}',
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_indicators_type ON public.threat_indicators(indicator_type);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_severity ON public.threat_indicators(severity);

-- 3. TLS Audits Table: Stored history of cryptographic handshakes
CREATE TABLE IF NOT EXISTS public.tls_audits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_to TIMESTAMPTZ NOT NULL,
    is_expired BOOLEAN NOT NULL DEFAULT FALSE,
    is_self_signed BOOLEAN NOT NULL DEFAULT FALSE,
    cipher_suite VARCHAR(128),
    protocol_version VARCHAR(32),
    subject_alt_names TEXT[] NOT NULL DEFAULT '{}',
    grade VARCHAR(4) NOT NULL DEFAULT 'A',
    audited_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tls_audits_domain ON public.tls_audits(domain);

-- 4. Row Level Security (RLS)
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_indicators ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tls_audits ENABLE ROW LEVEL SECURITY;

-- Allow public read of verified threat indicators
CREATE POLICY "Public can view verified threat indicators"
    ON public.threat_indicators
    FOR SELECT
    USING (is_verified = true OR auth.role() = 'authenticated');

-- Allow authenticated users to insert indicators for review
CREATE POLICY "Authenticated users can submit threat indicators"
    ON public.threat_indicators
    FOR INSERT
    TO authenticated
    WITH CHECK (auth.uid() = reported_by);

-- Allow users to view their own scans, or public scans with no user_id
CREATE POLICY "Users can view their scans"
    ON public.scans
    FOR SELECT
    USING (user_id IS NULL OR user_id = auth.uid());

CREATE POLICY "Users can create scans"
    ON public.scans
    FOR INSERT
    WITH CHECK (user_id IS NULL OR user_id = auth.uid());
```

---

## 6. Dependency List

### 6.1 Frontend & Node Server (npm packages)
- **Runtime**:
  - `react`: ^19.0.1
  - `react-dom`: ^19.0.1
  - `lucide-react`: ^0.546.0 (Icons for security indicators, shields, alerts)
  - `clsx`: ^2.1.1 (Conditional className compilation)
  - `tailwind-merge`: ^3.5.0 (Tailwind utility conflict resolution)
  - `class-variance-authority`: ^0.7.1 (shadcn/ui component variants)
  - `@radix-ui/react-slot`: ^1.2.4 (Polymorphic component rendering)
  - `@supabase/supabase-js`: ^2.99.0 (Supabase Auth and PostgreSQL interaction)
  - `express`: ^4.21.2 (Full-stack gateway & API server)
  - `dotenv`: ^17.2.3 (Environment loader)
  - `motion`: ^12.23.24 (Smooth security radar and transition animations)
- **DevDependencies**:
  - `vite`: ^8.3.0
  - `@vitejs/plugin-react`: ^6.1.1
  - `@tailwindcss/vite`: ^4.3.3
  - `tailwindcss`: ^4.3.3
  - `typescript`: ^7.0.2
  - `tsx`: ^4.21.0
  - `@types/express`: ^4.17.21
  - `@types/node`: ^22.14.0

### 6.2 Python FastAPI Backend (`backend/requirements.txt`)
- `fastapi>=0.115.0` (ASGI Web Framework)
- `uvicorn[standard]>=0.30.0` (Production ASGI Server)
- `pydantic>=2.8.0` (Strict schema validation)
- `pydantic-settings>=2.4.0` (Configuration management)
- `scikit-learn>=1.5.0` (Machine learning feature processing & models)
- `numpy>=1.26.0` (Matrix operations)
- `httpx>=0.27.0` (Async HTTP client for redirect following & headers inspection)
- `cryptography>=43.0.0` (x509 Certificate and TLS parsing)
- `supabase>=2.6.0` (Supabase Python SDK)
- `python-dotenv>=1.0.0` (Environment variable loading)

---

## 7. Phased Implementation Roadmap
- **Phase 1: Foundation (Current Turn)**:
  - Responsive Application Shell (Header, Sidebar, Navigation, Live Health Banner)
  - Routing and View management (Dashboard, Scanner, TLS, Threat Intel, System Health)
  - Frontend API Client (`apiClient.ts`) with typed contracts, fallback modes, and error normalization
  - Full FastAPI microservice codebase (`backend/app/*`) with clean architecture
  - Multi-subsystem Health Check endpoint (`/api/v1/health`)
  - Full-stack Node/Express gateway (`server.ts`) serving port 3000 with Vite middleware integration
  - Environment variable configuration (.env.example) and error handling
- **Phase 2: Core Analysis Engines**:
  - Full ML inference pipeline with scikit-learn model serialization
  - Deep lexical and domain heuristic extractor
  - TLS socket handshake validator with x509 chain auditor
- **Phase 3: Persistence & Threat Intel**:
  - Supabase database migrations and RLS enforcement
  - Community indicator submission and reputation scoring
  - Automated threat feed polling
