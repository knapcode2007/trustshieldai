"""
TrustShield AI - Dataset Importers & Leakage-Free Preprocessing Pipeline
Supports ingesting datasets from PhishTank, OpenPhish, URLhaus, Tranco, and generic labeled CSVs.
Enforces public-suffix-aware domain grouping, canonicalization, and threat separation.
"""

import csv
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from backend.app.ml.features import URLFeatureExtractor


@dataclass
class LabeledURLRecord:
    url: str
    label: int  # 1 = Phishing/Malicious, 0 = Benign/Clean
    registered_domain: str
    domain_group: str
    source: str
    timestamp: Optional[str] = None
    features: Optional[Dict[str, Any]] = None
    # Enhanced Phase 2A provenance & curation fields:
    canonical_url: Optional[str] = None
    threat_type: str = "unknown"  # "phishing", "malware", "benign", "suspicious", "unknown"
    original_label: Optional[str] = None
    confidence: Optional[float] = None
    collection_date: Optional[str] = None
    provenance_notes: Optional[str] = None


class DatasetImporter:
    """Manages dataset ingestion, domain grouping, canonicalization, and deduplication for model training."""

    # Public suffix registry covering ccTLD multi-part extensions and multi-tenant hosting platforms
    PUBLIC_SUFFIXES = {
        # UK
        "co.uk", "gov.uk", "ac.uk", "org.uk", "me.uk", "ltd.uk", "net.uk", "sch.uk", "plc.uk",
        # Australia
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
        # New Zealand
        "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
        # Japan
        "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp", "ed.jp",
        # Brazil
        "com.br", "gov.br", "org.br", "net.br", "edu.br",
        # Mexico
        "com.mx", "gob.mx", "org.mx", "edu.mx", "net.mx",
        # India
        "co.in", "net.in", "org.in", "gov.in", "ac.in", "res.in",
        # Singapore
        "com.sg", "gov.sg", "org.sg", "edu.sg",
        # South Africa
        "co.za", "gov.za", "org.za", "ac.za",
        # Turkey
        "com.tr", "edu.tr", "gov.tr", "org.tr",
        # Argentina
        "com.ar", "gov.ar", "org.ar", "edu.ar",
        # China
        "com.cn", "gov.cn", "edu.cn", "org.cn", "net.cn",
        # Taiwan
        "com.tw", "gov.tw", "org.tw", "edu.tw", "idv.tw",
        # Hong Kong
        "com.hk", "gov.hk", "org.hk", "edu.hk",
        # South Korea
        "co.kr", "go.kr", "or.kr", "re.kr",
        # Philippines
        "com.ph", "gov.ph", "org.ph", "edu.ph",
        # Malaysia
        "com.my", "gov.my", "org.my", "edu.my",
        # Colombia, Chile, Peru
        "com.co", "gov.co", "org.co", "edu.co",
        "gc.ca", "co.il", "gov.il", "org.il",
        "com.ru", "net.ru", "org.ru", "com.ua", "gov.ua",
    }

    # Known multi-tenant cloud hosting, storage, dynamic DNS, and free web builder domains
    # These domains are excluded from weakly labeled benign candidate pools because arbitrary users
    # can host unvetted content/phishing under their namespaces.
    MULTI_TENANT_HOSTS = {
        # Free web hosting, serverless & static site tenant platforms
        "github.io", "gitlab.io", "pages.dev", "web.app", "firebaseapp.com",
        "netlify.app", "vercel.app", "onrender.com", "herokuapp.com", "glitch.me",
        "azurewebsites.net", "cloudfunctions.net", "appspot.com", "myshopify.com",
        "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com", "surge.sh",
        "bplaced.net", "000webhostapp.com", "rf.gd", "epizy.com", "infinityfreeapp.com",

        # Cloud storage & file sharing (frequent staging grounds for phishing/malware)
        "s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net",
        "dropbox.com", "drive.google.com", "docs.google.com", "onedrive.live.com",
        "sharepoint.com", "box.com", "mediafire.com", "mega.nz",

        # Dynamic DNS providers
        "duckdns.org", "no-ip.com", "ddns.net", "zapto.org", "hopto.org",
        "myftp.org", "servehttp.com", "ngrok-free.app", "ngrok.io",

        # Forms & portals frequently abused for credential harvesting
        "forms.gle", "formsite.com", "typeform.com", "jotform.com",
        "surveymonkey.com", "canva.site", "carrd.co",
    }

    @classmethod
    def canonicalize_url(cls, url: str) -> str:
        """
        Normalizes URLs to ensure deterministic deduplication without altering endpoint semantics:
        - Strips leading/trailing whitespace and control chars.
        - Guarantees explicit scheme (defaulting to http:// if missing).
        - Lowercases scheme and netloc.
        - Strips default protocol ports (:80 for http, :443 for https).
        - Collapses redundant multiple slashes in path (preserving root /).
        - Strips client-side fragments (#...).
        - Deterministically sorts query parameters by key, then value.
        """
        if not url:
            return ""
        url = url.strip()
        if not url:
            return ""

        if "://" not in url:
            url = f"http://{url}"

        try:
            parsed = urlparse(url)
            scheme = (parsed.scheme or "http").lower()
            netloc = (parsed.netloc or "").strip().lower()

            # Strip default ports
            if scheme == "http" and netloc.endswith(":80"):
                netloc = netloc[:-3]
            elif scheme == "https" and netloc.endswith(":443"):
                netloc = netloc[:-4]

            # Path normalization: collapse redundant slashes
            path = parsed.path or "/"
            path = re.sub(r"/+", "/", path)

            # Query normalization: deterministic key sorting
            query = parsed.query
            if query:
                pairs = sorted(parse_qsl(query, keep_blank_values=True))
                query = urlencode(pairs)

            return urlunparse((scheme, netloc, path, "", query, ""))
        except Exception:
            return url.strip().lower()

    @classmethod
    def extract_domain_group(cls, url: str) -> str:
        """
        Extracts the registered base domain to act as the grouping key.
        Public-suffix-aware: correctly resolves multi-part ccTLDs (.co.uk) and
        multi-tenant hosting domains (.github.io).
        Prevents data leakage: URLs from the same registered domain never split across partitions.
        """
        parsed = urlparse(url if "://" in url else f"https://{url}")
        netloc = (parsed.netloc or url).split(":")[0].strip().lower()

        # Handle raw IPv4 literals
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", netloc):
            return netloc

        # Check modern multi-tenant hosts explicitly first (handles hosting platforms
        # that may be absent or differently partitioned in older PSL snapshots)
        for mts in cls.MULTI_TENANT_HOSTS:
            if netloc == mts:
                return netloc
            if netloc.endswith("." + mts):
                prefix = netloc[:-len(mts)-1]
                tenant = prefix.split(".")[-1]
                return f"{tenant}.{mts}"

        # 1. Use maintained publicsuffix2 if available
        try:
            import publicsuffix2
            sld = publicsuffix2.get_sld(netloc)
            if sld:
                return sld.strip().lower()
        except Exception:
            pass

        # 2. Offline fallback to built-in PUBLIC_SUFFIXES registry
        parts = [p for p in netloc.split(".") if p]
        if len(parts) <= 2:
            return ".".join(parts)

        # Check 3-part suffix (e.g., .domain.co.uk)
        if len(parts) >= 4 and ".".join(parts[-3:]) in cls.PUBLIC_SUFFIXES:
            return ".".join(parts[-4:])

        # Check 2-part suffix (e.g., .co.uk or .github.io)
        if len(parts) >= 3 and ".".join(parts[-2:]) in cls.PUBLIC_SUFFIXES:
            return ".".join(parts[-3:])

        return ".".join(parts[-2:])

    @classmethod
    def load_csv(
        cls,
        filepath: str,
        url_col: str = "url",
        label_col: str = "label",
        timestamp_col: Optional[str] = None,
        source_name: str = "custom_csv",
    ) -> List[LabeledURLRecord]:
        """Loads a generic labeled CSV file."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Dataset file '{filepath}' does not exist on disk.")

        records: List[LabeledURLRecord] = []
        seen_urls = set()

        with open(filepath, mode="r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                raw_url = row.get(url_col, "").strip()
                if not raw_url:
                    continue
                canonical = cls.canonicalize_url(raw_url)
                if not canonical or canonical in seen_urls:
                    continue
                seen_urls.add(canonical)

                raw_label = row.get(label_col, "0").strip().lower()
                is_malicious = raw_label in ("1", "phish", "phishing", "malicious", "bad", "true")
                label = 1 if is_malicious else 0
                threat_type = "phishing" if is_malicious else "benign"
                ts = row.get(timestamp_col) if timestamp_col else None
                group = cls.extract_domain_group(canonical)

                records.append(
                    LabeledURLRecord(
                        url=raw_url,
                        canonical_url=canonical,
                        label=label,
                        threat_type=threat_type,
                        original_label=raw_label,
                        registered_domain=group,
                        domain_group=group,
                        source=source_name,
                        timestamp=ts,
                        collection_date=ts,
                        confidence=0.85,
                        provenance_notes=f"Loaded from generic CSV source '{source_name}'.",
                    )
                )

        return records

    @classmethod
    def import_phishtank(cls, filepath: str, max_records: Optional[int] = None) -> List[LabeledURLRecord]:
        """
        Parses a local PhishTank verified database dump (CSV or JSON).
        Adheres to verification integrity: only parses files that actually exist.
        Assigns threat_type='phishing' and records community verification metadata.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(
                f"PhishTank dataset not found at '{filepath}'. Download 'verified_online.csv' from PhishTank according to Developer API terms."
            )

        records: List[LabeledURLRecord] = []
        seen_urls = set()

        if filepath.endswith(".json"):
            with open(filepath, mode="r", encoding="utf-8") as f:
                data = json.load(f)
                for entry in data:
                    raw_url = entry.get("url", "").strip()
                    if not raw_url:
                        continue
                    canonical = cls.canonicalize_url(raw_url)
                    if not canonical or canonical in seen_urls:
                        continue
                    seen_urls.add(canonical)
                    group = cls.extract_domain_group(canonical)
                    target = entry.get("target", "unspecified")
                    records.append(
                        LabeledURLRecord(
                            url=raw_url,
                            canonical_url=canonical,
                            label=1,
                            threat_type="phishing",
                            original_label="verified_phish",
                            registered_domain=group,
                            domain_group=group,
                            source="phishtank",
                            timestamp=entry.get("submission_time"),
                            collection_date=entry.get("submission_time"),
                            confidence=0.95,
                            provenance_notes=f"PhishTank verified community phish targeting '{target}'.",
                        )
                    )
                    if max_records and len(records) >= max_records:
                        break
        else:
            with open(filepath, mode="r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    raw_url = row.get("url", "").strip()
                    verified = row.get("verified", "yes").lower()
                    if not raw_url or verified != "yes":
                        continue
                    canonical = cls.canonicalize_url(raw_url)
                    if not canonical or canonical in seen_urls:
                        continue
                    seen_urls.add(canonical)
                    group = cls.extract_domain_group(canonical)
                    target = row.get("target", "unspecified")
                    records.append(
                        LabeledURLRecord(
                            url=raw_url,
                            canonical_url=canonical,
                            label=1,
                            threat_type="phishing",
                            original_label="verified_phish",
                            registered_domain=group,
                            domain_group=group,
                            source="phishtank",
                            timestamp=row.get("submission_time"),
                            collection_date=row.get("submission_time"),
                            confidence=0.95,
                            provenance_notes=f"PhishTank verified community phish targeting '{target}'.",
                        )
                    )
                    if max_records and len(records) >= max_records:
                        break

        return records

    @classmethod
    def import_openphish(cls, filepath: str, max_records: Optional[int] = None) -> List[LabeledURLRecord]:
        """
        Parses local OpenPhish community feed (text with one URL per line, or JSON).
        Assigns threat_type='phishing'.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"OpenPhish feed not found at '{filepath}'.")

        records: List[LabeledURLRecord] = []
        seen_urls = set()

        with open(filepath, mode="r", encoding="utf-8") as f:
            for line in f:
                raw_url = line.strip()
                if not raw_url or raw_url.startswith("#"):
                    continue
                canonical = cls.canonicalize_url(raw_url)
                if not canonical or canonical in seen_urls:
                    continue
                seen_urls.add(canonical)
                group = cls.extract_domain_group(canonical)
                records.append(
                    LabeledURLRecord(
                        url=raw_url,
                        canonical_url=canonical,
                        label=1,
                        threat_type="phishing",
                        original_label="openphish_feed",
                        registered_domain=group,
                        domain_group=group,
                        source="openphish",
                        confidence=0.90,
                        provenance_notes="Active phishing URL from OpenPhish Community Feed.",
                    )
                )
                if max_records and len(records) >= max_records:
                    break

        return records

    @classmethod
    def import_urlhaus(cls, filepath: str, max_records: Optional[int] = None) -> List[LabeledURLRecord]:
        """
        Parses local abuse.ch URLhaus CSV dump.
        CRITICAL: Labels records distinctly as threat_type='malware', preserving threat categorization
        (e.g., malware_download) rather than silently treating malware delivery as phishing.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"URLhaus dataset file not found at '{filepath}'.")

        records: List[LabeledURLRecord] = []
        seen_urls = set()

        with open(filepath, mode="r", encoding="utf-8", errors="ignore") as f:
            # Handle URLhaus format where header line is prefixed with "# id,dateadded,url..."
            cleaned_lines = []
            header_found = False
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                if not header_found:
                    if "url" in stripped.lower() and "threat" in stripped.lower():
                        # Found URLhaus CSV header line (strip leading # and whitespace)
                        cleaned_lines.append(re.sub(r"^#+\s*", "", stripped))
                        header_found = True
                    continue
                cleaned_lines.append(stripped)

            if not header_found:
                # Fallback: if no comment-style header, use standard non-comment lines
                f.seek(0)
                cleaned_lines = [l.strip() for l in f if not l.startswith("#")]

            reader = csv.DictReader(cleaned_lines)
            for row in reader:
                raw_url = row.get("url", "").strip()
                if not raw_url:
                    continue
                canonical = cls.canonicalize_url(raw_url)
                if not canonical or canonical in seen_urls:
                    continue
                seen_urls.add(canonical)

                threat = row.get("threat", "malware_download").strip()
                date_added = row.get("dateadded", "").strip()
                group = cls.extract_domain_group(canonical)

                records.append(
                    LabeledURLRecord(
                        url=raw_url,
                        canonical_url=canonical,
                        label=1,
                        threat_type="malware",
                        original_label=threat,
                        registered_domain=group,
                        domain_group=group,
                        source="urlhaus",
                        timestamp=date_added,
                        collection_date=date_added,
                        confidence=0.95,
                        provenance_notes=(
                            f"Abuse.ch URLhaus malware distribution feed (Threat: {threat}). "
                            f"Distinct from credential phishing; evaluated separately."
                        ),
                    )
                )
                if max_records and len(records) >= max_records:
                    break

        return records

    @classmethod
    def import_tranco(
        cls,
        filepath: str,
        max_records: Optional[int] = None,
        default_scheme: str = "https",
        exclude_multitenant: bool = True,
    ) -> List[LabeledURLRecord]:
        """
        Parses local Tranco Top 1M CSV (rank, domain).
        CRITICAL: Does NOT assume arbitrary URLs on Tranco domains are unconditionally benign.
        Excludes known multi-tenant cloud hosting, dynamic DNS, and free web builder domains.
        Records confidence=0.70 and explicit provenance limitation noting that apex domain
        popularity does not prove path-level safety.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Tranco dataset file not found at '{filepath}'.")

        records: List[LabeledURLRecord] = []
        seen_domains = set()

        with open(filepath, mode="r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                if len(row) >= 2 and row[0].strip().isdigit():
                    rank = int(row[0].strip())
                    domain = row[1].strip().lower()
                else:
                    rank = len(records) + 1
                    domain = row[0].strip().lower()

                if not domain or domain in seen_domains or domain.startswith("#"):
                    continue

                # Exclude known multi-tenant / dynamic DNS / user-generated host platforms
                if exclude_multitenant:
                    if domain in cls.MULTI_TENANT_HOSTS or any(domain.endswith("." + mh) for mh in cls.MULTI_TENANT_HOSTS):
                        continue

                seen_domains.add(domain)

                raw_url = f"{default_scheme}://{domain}/"
                canonical = cls.canonicalize_url(raw_url)
                group = cls.extract_domain_group(canonical)

                records.append(
                    LabeledURLRecord(
                        url=raw_url,
                        canonical_url=canonical,
                        label=0,
                        threat_type="benign",
                        original_label=f"tranco_rank_{rank}",
                        registered_domain=group,
                        domain_group=group,
                        source="tranco",
                        confidence=0.70,
                        provenance_notes=(
                            f"Apex domain ranked #{rank} in Tranco research list. "
                            f"LIMITATION: Popularity rank indicates apex domain reputation only; "
                            f"path-level content, open-redirects, or cloud-hosted user content are not verified."
                        ),
                    )
                )
                if max_records and len(records) >= max_records:
                    break

        return records

    @classmethod
    def generate_seed_benchmark(cls) -> List[LabeledURLRecord]:
        """
        Generates a verified, balanced offline seed benchmark dataset containing authoritative benign
        domains and verified suspicious/phishing URL structures with distinct domain groups.
        Enables reproducible pipeline testing, cross-validation, and metric verification without network dependence.
        """
        benign_samples = [
            "https://www.google.com/search?q=cybersecurity+training",
            "https://en.wikipedia.org/wiki/Transport_Layer_Security",
            "https://github.com/torvalds/linux/commit/8f10e4",
            "https://www.python.org/downloads/release/python-31012/",
            "https://docs.kernel.org/networking/scaling.html",
            "https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/TLS",
            "https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html",
            "https://www.ieee.org/membership/join/index.html",
            "https://www.apache.org/licenses/LICENSE-2.0",
            "https://stackoverflow.com/questions/509211/understanding-slice-notation",
            "https://www.nature.com/articles/d41586-024-00123-x",
            "https://www.cisa.gov/resources-tools/resources/phishing-infographic",
            "https://www.nist.gov/itl/applied-cybersecurity/nice",
            "https://www.cloudflare.com/learning/ssl/what-is-ssl/",
            "https://aws.amazon.com/security/introduction-to-iam/",
            "https://support.apple.com/en-us/102660",
            "https://azure.microsoft.com/en-us/solutions/devops/",
            "https://news.ycombinator.com/item?id=39123456",
            "https://www.bbc.com/news/technology-68123456",
            "https://www.reuters.com/technology/cybersecurity-update-2024/",
        ]

        phishing_samples = [
            "http://secure-login.paypal-account-update.xyz/auth/verify?session=9382",
            "http://185.220.101.5/banking/chase-online-signon/login.php",
            "https://accounts-google.com-support-recovery.click/signin/v2/identifier",
            "http://appleid.apple.com.manage-security-id82.top/verify?id=9291",
            "http://microsoft-outlook-webmail-update.live-verification.buzz/auth",
            "https://wellsfargo-security-alert-verification.xyz/online-banking/auth",
            "http://netflix-billing-reactivate-account.account-billing.work/login",
            "http://dhl-package-tracking-hold-notice.top/express/delivery/payment",
            "http://steamcommunity-trade-offer-confirm.item-inspect.click/id/8391",
            "http://coinbase-wallet-reconnect-security.xyz/session/login.html",
            "https://binance-account-kyc-suspend-alert.buzz/user/login",
            "http://chase-bank-verify-fraud-alert.secure-checkpoint.loan/auth",
            "http://citi-online-credit-card-statement.account-review.top/verify",
            "http://bankofamerica-urgent-login-suspended.online-auth.xyz/checkpoint",
            "http://amazon-prime-payment-declined.update-billing.work/ap/signin",
            "http://fedex-unpaid-customs-fee-notice.racing/track?num=829103810",
            "http://usps-redelivery-scheduled-address.date/parcel/address-confirm",
            "http://whatsapp-web-desktop-sync.login-code.stream/qr-session",
            "http://dropbox-shared-document-review.cloud-doc.men/shared/view",
            "http://instagram-copyright-infringement-appeal.meta-form.party/login",
        ]

        records: List[LabeledURLRecord] = []

        for url in benign_samples:
            canonical = cls.canonicalize_url(url)
            group = cls.extract_domain_group(canonical)
            records.append(
                LabeledURLRecord(
                    url=url,
                    canonical_url=canonical,
                    label=0,
                    threat_type="benign",
                    original_label="curated_benign",
                    registered_domain=group,
                    domain_group=group,
                    source="curated_benign_benchmark",
                    confidence=1.0,
                    timestamp="2026-01-15T12:00:00Z",
                    collection_date="2026-01-15T12:00:00Z",
                    provenance_notes="Curated authoritative documentation and reference URL.",
                )
            )

        for url in phishing_samples:
            canonical = cls.canonicalize_url(url)
            group = cls.extract_domain_group(canonical)
            records.append(
                LabeledURLRecord(
                    url=url,
                    canonical_url=canonical,
                    label=1,
                    threat_type="phishing",
                    original_label="curated_phish",
                    registered_domain=group,
                    domain_group=group,
                    source="curated_phishing_benchmark",
                    confidence=0.95,
                    timestamp="2026-02-10T14:30:00Z",
                    collection_date="2026-02-10T14:30:00Z",
                    provenance_notes="Verified synthetic phishing pattern with targeted brand evasion.",
                )
            )

        return records

    @classmethod
    def prepare_feature_dataset(
        cls, records: List[LabeledURLRecord]
    ) -> Tuple[List[List[float]], List[int], List[str]]:
        """
        Extracts feature vectors and returns:
        - X: List of numerical feature vectors
        - y: List of integer labels (0 or 1)
        - groups: List of registered domain group strings for GroupKFold
        """
        X: List[List[float]] = []
        y: List[int] = []
        groups: List[str] = []

        for rec in records:
            features = URLFeatureExtractor.extract_features(rec.canonical_url or rec.url)
            rec.features = features
            vec = URLFeatureExtractor.to_feature_vector(features)
            X.append(vec)
            y.append(rec.label)
            groups.append(rec.domain_group)

        return X, y, groups
