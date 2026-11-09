-- ==============================================================================
-- TrustShield AI - Production Database Schema & Security Policies
-- Migration: 20261109000000_trustshield_schema.sql
-- Description: Idempotent schema initialization for users, scans, reports,
--              community submissions, watchlists, threat indicators, audit logs,
--              and authorized testing with hardened Row Level Security (RLS).
-- ==============================================================================

-- 1. Helper function for updating timestamps
CREATE OR REPLACE FUNCTION public.handle_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    NEW.updated_at = timezone('utc'::text, now());
    RETURN NEW;
END;
$$;

-- 2. User Profiles Table (Linked to auth.users)
CREATE TABLE IF NOT EXISTS public.user_profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT UNIQUE,
    display_name TEXT,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'moderator', 'admin')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- Trigger for user profile updated_at
DROP TRIGGER IF EXISTS set_user_profiles_updated_at ON public.user_profiles;
CREATE TRIGGER set_user_profiles_updated_at
    BEFORE UPDATE ON public.user_profiles
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_updated_at();

-- Auto-provision user profile on signup (Strictly enforces default 'user' role)
-- Security: Never trusts raw_user_meta_data for privileged role assignment.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
BEGIN
    INSERT INTO public.user_profiles (id, email, display_name, role)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name', split_part(NEW.email, '@', 1)),
        'user' -- Hardcoded default role. Role elevation requires administrative action.
    )
    ON CONFLICT (id) DO NOTHING;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_new_user();

-- Security: Prevent non-admin users from escalating their own role in user_profiles
CREATE OR REPLACE FUNCTION public.protect_user_profile_role()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
BEGIN
    -- Check if role is changing and user is not an administrator or service_role
    IF (OLD.role IS DISTINCT FROM NEW.role) THEN
        IF NOT (
            EXISTS (
                SELECT 1 FROM public.user_profiles
                WHERE id = auth.uid() AND role = 'admin'
            )
            OR (auth.jwt()->>'role' = 'service_role')
        ) THEN
            RAISE EXCEPTION 'Unauthorized: Only system administrators can alter user roles.';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS enforce_profile_role_protection ON public.user_profiles;
CREATE TRIGGER enforce_profile_role_protection
    BEFORE UPDATE ON public.user_profiles
    FOR EACH ROW
    EXECUTE FUNCTION public.protect_user_profile_role();

-- 3. Scans & Forensic Reports Table
CREATE TABLE IF NOT EXISTS public.scans (
    scan_id TEXT PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    raw_url TEXT NOT NULL,
    canonical_url TEXT NOT NULL,
    domain TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'completed' CHECK (state IN ('queued', 'running', 'completed', 'partial', 'failed')),
    progress_percent INTEGER NOT NULL DEFAULT 100 CHECK (progress_percent >= 0 AND progress_percent <= 100),
    verdict TEXT NOT NULL CHECK (verdict IN ('clean', 'suspicious', 'phishing', 'malicious')),
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    confidence NUMERIC(3, 2) NOT NULL DEFAULT 0.85 CHECK (confidence >= 0.0 AND confidence <= 1.0),
    heuristics JSONB NOT NULL DEFAULT '{}'::jsonb,
    ml_prediction JSONB DEFAULT '{}'::jsonb,
    tls_summary JSONB,
    security_headers JSONB,
    analysis_coverage JSONB,
    threat_feed_matches JSONB DEFAULT '[]'::jsonb,
    threat_intel_summary JSONB DEFAULT '{}'::jsonb,
    evidence JSONB DEFAULT '[]'::jsonb,
    recommendations JSONB DEFAULT '[]'::jsonb,
    module_statuses JSONB DEFAULT '{}'::jsonb,
    error_payload JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    completed_at TIMESTAMPTZ
);

-- Indices for Scans
CREATE INDEX IF NOT EXISTS idx_scans_domain ON public.scans (domain);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON public.scans (verdict);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON public.scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_user_id ON public.scans (user_id);
CREATE INDEX IF NOT EXISTS idx_scans_canonical_url ON public.scans (canonical_url);

-- 4. Community Reports Table
CREATE TABLE IF NOT EXISTS public.community_reports (
    id TEXT PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    target_url TEXT NOT NULL,
    domain TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    targeted_brand TEXT,
    description TEXT NOT NULL,
    reporter_handle TEXT NOT NULL DEFAULT 'community_member',
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'dismissed')),
    confirmations_count INTEGER NOT NULL DEFAULT 1 CHECK (confirmations_count >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    moderated_at TIMESTAMPTZ,
    moderator_note TEXT
);

-- Indices for Community Reports
CREATE INDEX IF NOT EXISTS idx_community_reports_status ON public.community_reports (status);
CREATE INDEX IF NOT EXISTS idx_community_reports_domain ON public.community_reports (domain);
CREATE INDEX IF NOT EXISTS idx_community_reports_created_at ON public.community_reports (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_community_reports_user_id ON public.community_reports (user_id);

-- Secure Voting RPC Function (Prevents unauthorized column tampering on community_reports)
CREATE OR REPLACE FUNCTION public.upvote_community_report(report_id TEXT)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    new_count INTEGER;
BEGIN
    UPDATE public.community_reports
    SET confirmations_count = confirmations_count + 1
    WHERE id = report_id
    RETURNING confirmations_count INTO new_count;

    IF new_count IS NULL THEN
        RAISE EXCEPTION 'Report % not found', report_id;
    END IF;

    RETURN new_count;
END;
$$;

-- 5. Watchlist Table
CREATE TABLE IF NOT EXISTS public.watchlist (
    id TEXT PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    domain TEXT NOT NULL,
    label TEXT NOT NULL,
    alert_threshold INTEGER NOT NULL DEFAULT 40 CHECK (alert_threshold >= 0 AND alert_threshold <= 100),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused')),
    last_scanned_at TIMESTAMPTZ,
    last_risk_score INTEGER CHECK (last_risk_score IS NULL OR (last_risk_score >= 0 AND last_risk_score <= 100)),
    last_verdict TEXT CHECK (last_verdict IS NULL OR last_verdict IN ('clean', 'suspicious', 'phishing', 'malicious')),
    added_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- Indices for Watchlist
CREATE INDEX IF NOT EXISTS idx_watchlist_user_id ON public.watchlist (user_id);
CREATE INDEX IF NOT EXISTS idx_watchlist_domain ON public.watchlist (domain);
CREATE INDEX IF NOT EXISTS idx_watchlist_added_at ON public.watchlist (added_at DESC);

-- 6. Threat Indicators Table (IOCs)
CREATE TABLE IF NOT EXISTS public.threat_indicators (
    id TEXT PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    indicator_value TEXT NOT NULL,
    indicator_type TEXT NOT NULL CHECK (indicator_type IN ('url', 'domain', 'ip', 'sha256')),
    threat_category TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    confidence INTEGER NOT NULL DEFAULT 80 CHECK (confidence >= 0 AND confidence <= 100),
    source TEXT NOT NULL DEFAULT 'TrustShield Research',
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],
    is_verified BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    verified_at TIMESTAMPTZ,
    verified_by TEXT
);

-- Indices for Threat Indicators
CREATE INDEX IF NOT EXISTS idx_threat_indicators_type ON public.threat_indicators (indicator_type);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_severity ON public.threat_indicators (severity);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_verified ON public.threat_indicators (is_verified);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_value ON public.threat_indicators (indicator_value);

-- 7. Admin Audit Logs Table
CREATE TABLE IF NOT EXISTS public.admin_audit_logs (
    id TEXT PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL CHECK (target_type IN ('indicator', 'report', 'watchlist')),
    target_id TEXT NOT NULL,
    target_value TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected', 'modified')),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    actor TEXT NOT NULL DEFAULT 'Admin Moderator',
    reason TEXT
);

-- Indices for Admin Audit Logs
CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_timestamp ON public.admin_audit_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_target ON public.admin_audit_logs (target_type, target_id);

-- 8. Authorized Domain Security Testing Table (OWASP ZAP)
CREATE TABLE IF NOT EXISTS public.authorized_domains (
    domain TEXT PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    owner_email TEXT NOT NULL,
    challenge_token TEXT NOT NULL,
    txt_record_name TEXT NOT NULL,
    txt_record_value TEXT NOT NULL,
    http_challenge_path TEXT NOT NULL,
    http_challenge_content TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT false,
    auth_token TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE INDEX IF NOT EXISTS idx_authorized_domains_user_id ON public.authorized_domains (user_id);
CREATE INDEX IF NOT EXISTS idx_authorized_domains_expires_at ON public.authorized_domains (expires_at);

-- ==============================================================================
-- 9. Hardened Row Level Security (RLS) Configuration
-- ==============================================================================

ALTER TABLE public.user_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.community_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.watchlist ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_indicators ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.admin_audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.authorized_domains ENABLE ROW LEVEL SECURITY;

-- Helper to check if current user is admin/moderator
-- Security: SET search_path = public, auth prevents search_path poisoning
CREATE OR REPLACE FUNCTION public.is_admin_or_moderator()
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, auth
AS $$
BEGIN
    RETURN (
        EXISTS (
            SELECT 1 FROM public.user_profiles
            WHERE id = auth.uid() AND role IN ('admin', 'moderator')
        )
        OR (auth.jwt()->>'role' = 'service_role')
    );
END;
$$;

-- --- User Profiles Policies ---
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'user_profiles' AND policyname = 'user_profiles_read_own') THEN
        CREATE POLICY user_profiles_read_own ON public.user_profiles
            FOR SELECT USING (auth.uid() = id OR public.is_admin_or_moderator());
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'user_profiles' AND policyname = 'user_profiles_update_own') THEN
        CREATE POLICY user_profiles_update_own ON public.user_profiles
            FOR UPDATE USING (auth.uid() = id OR public.is_admin_or_moderator());
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'user_profiles' AND policyname = 'user_profiles_service_role_all') THEN
        CREATE POLICY user_profiles_service_role_all ON public.user_profiles
            FOR ALL USING (auth.jwt()->>'role' = 'service_role');
    END IF;
END $$;

-- --- Scans Policies ---
-- Scans are public threat intelligence lookups; user_id cannot be forged
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'scans' AND policyname = 'scans_select_public') THEN
        CREATE POLICY scans_select_public ON public.scans
            FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'scans' AND policyname = 'scans_insert_public') THEN
        CREATE POLICY scans_insert_public ON public.scans
            FOR INSERT WITH CHECK (user_id IS NULL OR auth.uid() = user_id OR auth.jwt()->>'role' = 'service_role');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'scans' AND policyname = 'scans_service_role_all') THEN
        CREATE POLICY scans_service_role_all ON public.scans
            FOR ALL USING (auth.jwt()->>'role' = 'service_role');
    END IF;
END $$;

-- --- Community Reports Policies ---
-- Security: Public can insert pending reports, but cannot update or moderate them.
-- Moderation and updates strictly require admin/moderator role or service_role.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'community_reports' AND policyname = 'community_reports_select_public') THEN
        CREATE POLICY community_reports_select_public ON public.community_reports
            FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'community_reports' AND policyname = 'community_reports_insert_public') THEN
        CREATE POLICY community_reports_insert_public ON public.community_reports
            FOR INSERT WITH CHECK (
                status = 'pending' -- New community reports must always enter with pending status
                AND (user_id IS NULL OR auth.uid() = user_id OR auth.jwt()->>'role' = 'service_role')
            );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'community_reports' AND policyname = 'community_reports_modify_admin') THEN
        CREATE POLICY community_reports_modify_admin ON public.community_reports
            FOR UPDATE USING (public.is_admin_or_moderator() OR auth.jwt()->>'role' = 'service_role');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'community_reports' AND policyname = 'community_reports_service_role_all') THEN
        CREATE POLICY community_reports_service_role_all ON public.community_reports
            FOR ALL USING (auth.jwt()->>'role' = 'service_role');
    END IF;
END $$;

-- --- Watchlist Policies ---
-- Security: Baseline system demo items (user_id IS NULL) are readable by all, but can only be modified by admins/service_role.
-- Authenticated users have full control over their own watchlist rows.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'watchlist' AND policyname = 'watchlist_select') THEN
        CREATE POLICY watchlist_select ON public.watchlist
            FOR SELECT USING (user_id IS NULL OR auth.uid() = user_id OR public.is_admin_or_moderator());
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'watchlist' AND policyname = 'watchlist_insert') THEN
        CREATE POLICY watchlist_insert ON public.watchlist
            FOR INSERT WITH CHECK (auth.uid() = user_id OR auth.jwt()->>'role' = 'service_role');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'watchlist' AND policyname = 'watchlist_modify') THEN
        CREATE POLICY watchlist_modify ON public.watchlist
            FOR ALL USING (auth.uid() = user_id OR public.is_admin_or_moderator() OR auth.jwt()->>'role' = 'service_role');
    END IF;
END $$;

-- --- Threat Indicators Policies ---
-- Security: Anyone can read IOCs; unverified contributions can be submitted,
-- but the is_verified flag can ONLY be set to true by administrators/service_role.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'threat_indicators' AND policyname = 'threat_indicators_select') THEN
        CREATE POLICY threat_indicators_select ON public.threat_indicators
            FOR SELECT USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'threat_indicators' AND policyname = 'threat_indicators_insert') THEN
        CREATE POLICY threat_indicators_insert ON public.threat_indicators
            FOR INSERT WITH CHECK (
                is_verified = false -- Unverified by default for community submissions
                OR public.is_admin_or_moderator()
                OR auth.jwt()->>'role' = 'service_role'
            );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'threat_indicators' AND policyname = 'threat_indicators_update_admin') THEN
        CREATE POLICY threat_indicators_update_admin ON public.threat_indicators
            FOR UPDATE USING (public.is_admin_or_moderator() OR auth.jwt()->>'role' = 'service_role');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'threat_indicators' AND policyname = 'threat_indicators_service_role_all') THEN
        CREATE POLICY threat_indicators_service_role_all ON public.threat_indicators
            FOR ALL USING (auth.jwt()->>'role' = 'service_role');
    END IF;
END $$;

-- --- Admin Audit Logs Policies ---
-- Security: Read and insert operations strictly limited to admins/moderators or service_role.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'admin_audit_logs' AND policyname = 'admin_audit_logs_select') THEN
        CREATE POLICY admin_audit_logs_select ON public.admin_audit_logs
            FOR SELECT USING (public.is_admin_or_moderator() OR auth.jwt()->>'role' = 'service_role');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'admin_audit_logs' AND policyname = 'admin_audit_logs_insert') THEN
        CREATE POLICY admin_audit_logs_insert ON public.admin_audit_logs
            FOR INSERT WITH CHECK (public.is_admin_or_moderator() OR auth.jwt()->>'role' = 'service_role');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'admin_audit_logs' AND policyname = 'admin_audit_logs_service_role_all') THEN
        CREATE POLICY admin_audit_logs_service_role_all ON public.admin_audit_logs
            FOR ALL USING (auth.jwt()->>'role' = 'service_role');
    END IF;
END $$;

-- --- Authorized Domains Policies ---
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'authorized_domains' AND policyname = 'authorized_domains_select') THEN
        CREATE POLICY authorized_domains_select ON public.authorized_domains
            FOR SELECT USING (user_id IS NULL OR auth.uid() = user_id OR auth.jwt()->>'role' = 'service_role');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'authorized_domains' AND policyname = 'authorized_domains_modify') THEN
        CREATE POLICY authorized_domains_modify ON public.authorized_domains
            FOR ALL USING (user_id IS NULL OR auth.uid() = user_id OR auth.jwt()->>'role' = 'service_role');
    END IF;
END $$;

-- ==============================================================================
-- 10. Baseline Seed Data (Idempotent, Clearly Marked as [DEMO DATA])
-- ==============================================================================

-- Seed Threat Indicators (IOCs)
-- Clearly tagged with 'demo_data' and 'system_seed' to distinguish from live telemetry
INSERT INTO public.threat_indicators (
    id, indicator_value, indicator_type, threat_category, severity, confidence, source, tags, is_verified, created_at
) VALUES
    (
        'ioc-1001',
        'secure-paypal-update-alert.xyz',
        'domain',
        'Credential Harvester',
        'critical',
        98,
        'TrustShield Research (Baseline Seed)',
        ARRAY['paypal', 'credential-theft', 'phishing', 'demo_data', 'system_seed'],
        true,
        '2026-11-08T18:22:10Z'
    ),
    (
        'ioc-1002',
        'account-verification-office365-login.net',
        'domain',
        'Spearphishing Portal',
        'high',
        95,
        'Community Telemetry (Baseline Seed)',
        ARRAY['microsoft', 'o365', 'corporate-spoof', 'demo_data', 'system_seed'],
        true,
        '2026-11-09T01:45:00Z'
    ),
    (
        'ioc-1003',
        '185.220.101.5',
        'ip',
        'Malicious C2 Node',
        'critical',
        92,
        'AbuseIPDB Feed (Baseline Seed)',
        ARRAY['c2', 'bulletproof-hosting', 'botnet', 'demo_data', 'system_seed'],
        true,
        '2026-11-09T04:12:30Z'
    )
ON CONFLICT (id) DO NOTHING;

-- Seed Community Reports
-- Descriptions explicitly prefixed with [DEMO DATA]
INSERT INTO public.community_reports (
    id, target_url, domain, threat_type, targeted_brand, description, reporter_handle, severity, status, confirmations_count, created_at, moderated_at, moderator_note
) VALUES
    (
        'cr-101',
        'https://support-netflix-billing-update.cc/login',
        'support-netflix-billing-update.cc',
        'Phishing / Billing Scam',
        'Netflix',
        '[DEMO DATA] SMS phishing message claiming membership payment was declined, redirecting to a cloned Netflix credential and credit card harvest form.',
        'infosec_hawk',
        'high',
        'verified',
        8,
        '2026-11-08T14:30:00Z',
        '2026-11-08T15:00:00Z',
        '[DEMO DATA] Confirmed active spearphishing credential kit.'
    ),
    (
        'cr-102',
        'https://metamask-security-sync-auth.io',
        'metamask-security-sync-auth.io',
        'Web3 Seed Phrase Drainer',
        'MetaMask',
        '[DEMO DATA] Malicious crypto phishing site impersonating MetaMask recovery workflow to drain BIP-39 recovery seed phrases.',
        'crypto_sentry',
        'critical',
        'pending',
        4,
        '2026-11-09T02:15:00Z',
        NULL,
        NULL
    )
ON CONFLICT (id) DO NOTHING;

-- Seed Watchlist Items
-- Labels explicitly prefixed with [DEMO]
INSERT INTO public.watchlist (
    id, target, domain, label, alert_threshold, status, last_scanned_at, last_risk_score, last_verdict, added_at
) VALUES
    (
        'wl-01',
        'https://github.com',
        'github.com',
        '[DEMO] Developer Infrastructure',
        40,
        'active',
        '2026-11-09T08:00:00Z',
        2,
        'clean',
        '2026-11-08T10:00:00Z'
    ),
    (
        'wl-02',
        'https://suspicious-billing-portal.top',
        'suspicious-billing-portal.top',
        '[DEMO] Customer Phishing Report',
        30,
        'active',
        '2026-11-09T08:05:00Z',
        82,
        'phishing',
        '2026-11-08T11:30:00Z'
    )
ON CONFLICT (id) DO NOTHING;

-- Seed Admin Audit Logs
-- Actions and reasons clearly marked with [SYSTEM SEED / DEMO]
INSERT INTO public.admin_audit_logs (
    id, action, target_type, target_id, target_value, decision, timestamp, actor, reason
) VALUES
    (
        'audit-01',
        'MODERATE_COMMUNITY_REPORT',
        'report',
        'cr-101',
        'support-netflix-billing-update.cc',
        'approved',
        '2026-11-08T15:00:00Z',
        'Senior Threat Analyst',
        '[SYSTEM SEED / DEMO] Verified live phishing kit harvesting credentials and payment cards.'
    )
ON CONFLICT (id) DO NOTHING;
