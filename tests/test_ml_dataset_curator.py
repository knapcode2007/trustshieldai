"""
Unit & Integration Test Suite for Phase 2A Dataset Acquisition & Curation Pipeline
Validates:
1. URL canonicalization and public-suffix-aware domain grouping.
2. Feed parsers with small synthetic offline fixtures (PhishTank, OpenPhish, URLhaus, Tranco).
3. Exact duplicate deduplication and cross-source conflict detection (quarantine policy).
4. Threat-type segregation (URLhaus malware kept distinct from phishing).
5. Dataset quality report generation (JSON and Markdown).
6. Partitioning with zero domain overlap.
7. CSV and JSONL dataset export with provenance.
"""

import json
import os
import tempfile
import unittest

from backend.app.ml.curator import DatasetCurator, DatasetQualityReport
from backend.app.ml.dataset_importer import DatasetImporter, LabeledURLRecord


class TestURLCanonicalization(unittest.TestCase):
    """Tests deterministic URL canonicalization without modifying endpoint semantics."""

    def test_canonicalize_normalizes_case_scheme_and_default_ports(self):
        url1 = "HTTPS://EXAMPLE.COM:443/login//verify?b=2&a=1#token"
        canon1 = DatasetImporter.canonicalize_url(url1)
        self.assertEqual(canon1, "https://example.com/login/verify?a=1&b=2")

        url2 = "http://EXAMPLE.COM:80/path/to/resource"
        canon2 = DatasetImporter.canonicalize_url(url2)
        self.assertEqual(canon2, "http://example.com/path/to/resource")

        # Non-default port is preserved
        url3 = "http://example.com:8080/login"
        canon3 = DatasetImporter.canonicalize_url(url3)
        self.assertEqual(canon3, "http://example.com:8080/login")

    def test_canonicalize_preserves_distinct_endpoints(self):
        """Verifies that distinct URLs are never erroneously merged."""
        url_a = "https://example.com/login?user=alice"
        url_b = "https://example.com/login?user=bob"
        url_c = "https://example.com/account"

        canon_a = DatasetImporter.canonicalize_url(url_a)
        canon_b = DatasetImporter.canonicalize_url(url_b)
        canon_c = DatasetImporter.canonicalize_url(url_c)

        self.assertNotEqual(canon_a, canon_b)
        self.assertNotEqual(canon_a, canon_c)
        self.assertNotEqual(canon_b, canon_c)

    def test_canonicalize_handles_schemeless_and_root(self):
        canon = DatasetImporter.canonicalize_url("example.com")
        self.assertEqual(canon, "http://example.com/")

        canon_empty = DatasetImporter.canonicalize_url("")
        self.assertEqual(canon_empty, "")


class TestPublicSuffixDomainGrouping(unittest.TestCase):
    """Tests registered-domain grouping using multi-part ccTLDs and multi-tenant suffixes."""

    def test_standard_domains(self):
        self.assertEqual(DatasetImporter.extract_domain_group("https://login.paypal.com/auth"), "paypal.com")
        self.assertEqual(DatasetImporter.extract_domain_group("https://google.com"), "google.com")

    def test_multipart_cctlds(self):
        self.assertEqual(DatasetImporter.extract_domain_group("https://auth.portal.company.co.uk/test"), "company.co.uk")
        self.assertEqual(DatasetImporter.extract_domain_group("https://dept.univ.edu.au/research"), "univ.edu.au")
        self.assertEqual(DatasetImporter.extract_domain_group("https://service.gov.in/portal"), "service.gov.in")

    def test_multitenant_hosting_isolation(self):
        """Subdomains of multi-tenant cloud platforms must be isolated into distinct registered groups."""
        grp_alice = DatasetImporter.extract_domain_group("https://alice.github.io/blog")
        grp_bob = DatasetImporter.extract_domain_group("https://bob.github.io/app")
        self.assertEqual(grp_alice, "alice.github.io")
        self.assertEqual(grp_bob, "bob.github.io")
        self.assertNotEqual(grp_alice, grp_bob)

        grp_sub = DatasetImporter.extract_domain_group("https://sub.myproject.pages.dev/auth")
        self.assertEqual(grp_sub, "myproject.pages.dev")

    def test_ipv4_host_literals(self):
        self.assertEqual(DatasetImporter.extract_domain_group("http://185.220.101.5:8080/login"), "185.220.101.5")


class TestSyntheticFeedParsers(unittest.TestCase):
    """Tests feed importers using small synthetic offline files."""

    def test_import_urlhaus_csv_segregates_malware_threat_type(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".csv", delete=False) as f:
            f.write("# Abuse.ch URLhaus CSV\n")
            f.write("# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n")
            f.write('"1001","2026-02-10 12:00:00","http://malware-host.xyz/payload.exe","online","2026-02-10","malware_download","exe","https://urlhaus.abuse.ch/","analyst1"\n')
            f.write('"1002","2026-02-10 13:00:00","http://drop-site.top/loader.sh","online","2026-02-10","elf_download","sh,elf","https://urlhaus.abuse.ch/","analyst2"\n')
            temp_path = f.name

        try:
            records = DatasetImporter.import_urlhaus(temp_path)
            self.assertEqual(len(records), 2)
            for r in records:
                self.assertEqual(r.source, "urlhaus")
                # CRITICAL: threat_type MUST be 'malware', not conflated with phishing
                self.assertEqual(r.threat_type, "malware")
                self.assertEqual(r.label, 1)
                self.assertIn("malware", r.provenance_notes.lower())
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_import_tranco_records_provenance_and_limitations(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".csv", delete=False) as f:
            f.write("1,google.com\n")
            f.write("2,github.com\n")
            temp_path = f.name

        try:
            records = DatasetImporter.import_tranco(temp_path)
            self.assertEqual(len(records), 2)
            r0 = records[0]
            self.assertEqual(r0.source, "tranco")
            self.assertEqual(r0.label, 0)
            self.assertEqual(r0.threat_type, "benign")
            self.assertEqual(r0.confidence, 0.70)
            self.assertIn("tranco_rank_1", r0.original_label)
            self.assertIn("LIMITATION", r0.provenance_notes)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_import_tranco_excludes_multitenant_hosts(self):
        """Verifies that known multi-tenant and dynamic DNS hosts are excluded from benign pool."""
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".csv", delete=False) as f:
            f.write("1,google.com\n")
            f.write("2,duckdns.org\n")            # Dynamic DNS host
            f.write("3,firebaseapp.com\n")        # Multi-tenant host
            f.write("4,blob.core.windows.net\n")  # Cloud storage host
            f.write("5,wikipedia.org\n")
            temp_path = f.name

        try:
            records = DatasetImporter.import_tranco(temp_path, exclude_multitenant=True)
            domains = [r.registered_domain for r in records]
            self.assertIn("google.com", domains)
            self.assertIn("wikipedia.org", domains)
            self.assertNotIn("duckdns.org", domains)
            self.assertNotIn("firebaseapp.com", domains)
            self.assertNotIn("blob.core.windows.net", domains)
            self.assertEqual(len(records), 2)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_import_phishtank_csv(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".csv", delete=False) as f:
            f.write("phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n")
            f.write('991,"http://paypal-security-update.xyz/login","http://phishtank.com/991","2026-02-10T12:00:00Z","yes","2026-02-10T12:05:00Z","yes","PayPal"\n')
            temp_path = f.name

        try:
            records = DatasetImporter.import_phishtank(temp_path)
            self.assertEqual(len(records), 1)
            r = records[0]
            self.assertEqual(r.source, "phishtank")
            self.assertEqual(r.threat_type, "phishing")
            self.assertEqual(r.label, 1)
            self.assertEqual(r.confidence, 0.95)
            self.assertIn("PayPal", r.provenance_notes)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


class TestDatasetCurationAndConflictResolution(unittest.TestCase):
    """Tests deduplication, conflict detection, and quarantine policies."""

    def test_deduplication_of_exact_duplicate_urls(self):
        raw_records = [
            LabeledURLRecord(url="https://example.com/login?a=1&b=2", label=1, registered_domain="example.com", domain_group="example.com", source="feed1", threat_type="phishing"),
            # Different query param order - canonicalizes to identical URL
            LabeledURLRecord(url="https://example.com/login?b=2&a=1", label=1, registered_domain="example.com", domain_group="example.com", source="feed2", threat_type="phishing"),
        ]

        curator = DatasetCurator()
        curated, report = curator.curate(raw_records)

        self.assertEqual(len(curated), 1)
        self.assertEqual(report.duplicate_count, 1)
        self.assertEqual(report.conflict_count, 0)
        self.assertIn("feed1", curated[0].provenance_notes)
        self.assertIn("feed2", curated[0].provenance_notes)

    def test_conflict_detection_and_quarantine_policy(self):
        """When different feeds report conflicting labels for identical URL, quarantine drops it."""
        raw_records = [
            # Benign feed claims clean
            LabeledURLRecord(url="https://contested-domain.com/login", label=0, registered_domain="contested-domain.com", domain_group="contested-domain.com", source="benign_feed", threat_type="benign"),
            # Phish feed claims phishing
            LabeledURLRecord(url="https://contested-domain.com/login", label=1, registered_domain="contested-domain.com", domain_group="contested-domain.com", source="phish_feed", threat_type="phishing"),
            # Uncontested clean URL
            LabeledURLRecord(url="https://clean-site.org/index", label=0, registered_domain="clean-site.org", domain_group="clean-site.org", source="benign_feed", threat_type="benign"),
        ]

        curator = DatasetCurator(conflict_policy="quarantine")
        curated, report = curator.curate(raw_records)

        # Contested URL must be quarantined and dropped
        self.assertEqual(len(curated), 1)
        self.assertEqual(curated[0].url, "https://clean-site.org/index")
        self.assertEqual(report.conflict_count, 1)
        self.assertEqual(report.conflicts[0]["url"], "https://contested-domain.com/login")
        self.assertEqual(report.conflicts[0]["resolution"], "quarantine")

    def test_conflict_policy_prefer_malicious(self):
        raw_records = [
            LabeledURLRecord(url="https://contested.com/auth", label=0, registered_domain="contested.com", domain_group="contested.com", source="b_feed", threat_type="benign"),
            LabeledURLRecord(url="https://contested.com/auth", label=1, registered_domain="contested.com", domain_group="contested.com", source="p_feed", threat_type="phishing"),
        ]

        curator = DatasetCurator(conflict_policy="prefer_malicious")
        curated, report = curator.curate(raw_records)

        self.assertEqual(len(curated), 1)
        self.assertEqual(curated[0].label, 1)
        self.assertIn("Conflict resolved", curated[0].provenance_notes)

    def test_threat_type_segregation_for_malware(self):
        """URLhaus malware URLs are separated from binary phishing training set by default."""
        raw_records = [
            LabeledURLRecord(url="https://phish1.com/login", label=1, registered_domain="phish1.com", domain_group="phish1.com", source="phishtank", threat_type="phishing"),
            LabeledURLRecord(url="https://clean1.com/about", label=0, registered_domain="clean1.com", domain_group="clean1.com", source="tranco", threat_type="benign"),
            LabeledURLRecord(url="https://malware1.com/payload.exe", label=1, registered_domain="malware1.com", domain_group="malware1.com", source="urlhaus", threat_type="malware"),
        ]

        # By default include_malware_in_binary=False
        curator = DatasetCurator(include_malware_in_binary=False)
        curated, report = curator.curate(raw_records)

        # Retained curated set contains only phishing and benign
        self.assertEqual(len(curated), 2)
        threat_types = set(r.threat_type for r in curated)
        self.assertNotIn("malware", threat_types)

        # Malware records are kept separated in curator.malware_records
        self.assertEqual(len(curator.malware_records), 1)
        self.assertEqual(curator.malware_records[0].url, "https://malware1.com/payload.exe")


class TestQualityReportAndPartitioning(unittest.TestCase):
    """Tests report generation, JSON/Markdown export, and zero domain leakage."""

    def test_quality_report_outputs_valid_json_and_markdown(self):
        benchmark = DatasetImporter.generate_seed_benchmark()
        curator = DatasetCurator()
        curated, report = curator.curate(benchmark)

        # JSON serialization
        json_str = report.to_json()
        data = json.loads(json_str)
        self.assertEqual(data["summary"]["total_raw_records"], len(benchmark))
        self.assertEqual(data["summary"]["retained_records"], len(curated))
        self.assertGreater(data["domain_diversity"]["unique_domains"], 10)

        # Markdown serialization
        md_str = report.to_markdown()
        self.assertIn("# TrustShield AI — Dataset Quality & Provenance Report", md_str)
        self.assertIn("Source Ingestion Breakdown", md_str)
        self.assertIn("Domain Diversity", md_str)

    def test_curated_partitioning_guarantees_zero_domain_leakage(self):
        benchmark = DatasetImporter.generate_seed_benchmark()
        curator = DatasetCurator()
        curated, report = curator.curate(benchmark)

        train_recs, cal_recs, test_recs = curator.partition_dataset(curated, val_ratio=0.20, test_ratio=0.20, report=report)

        self.assertIsNotNone(report.partition_summary)
        p = report.partition_summary
        self.assertEqual(p["domain_overlap_count"], 0)
        self.assertFalse(p["domain_overlap_detected"])
        self.assertEqual(p["leakage_status"], "Zero Domain Overlap Verified")

        # Set math proof
        train_d = set(r.domain_group for r in train_recs)
        cal_d = set(r.domain_group for r in cal_recs)
        test_d = set(r.domain_group for r in test_recs)

        self.assertTrue(train_d.isdisjoint(cal_d))
        self.assertTrue(train_d.isdisjoint(test_d))
        self.assertTrue(cal_d.isdisjoint(test_d))

    def test_export_dataset_csv_and_jsonl(self):
        benchmark = DatasetImporter.generate_seed_benchmark()
        curator = DatasetCurator()
        curated, _ = curator.curate(benchmark)

        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "curated.csv")
            jsonl_path = os.path.join(tmpdir, "curated.jsonl")

            curator.export_dataset_csv(curated, csv_path)
            curator.export_dataset_jsonl(curated, jsonl_path)

            self.assertTrue(os.path.exists(csv_path))
            self.assertTrue(os.path.exists(jsonl_path))

            # Verify CSV content
            with open(csv_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                self.assertGreater(len(lines), len(curated))
                self.assertIn("canonical_url", lines[0])
                self.assertIn("provenance_notes", lines[0])

            # Verify JSONL content
            with open(jsonl_path, "r", encoding="utf-8") as f:
                json_lines = f.readlines()
                self.assertEqual(len(json_lines), len(curated))
                first_rec = json.loads(json_lines[0])
                self.assertIn("canonical_url", first_rec)
                self.assertIn("threat_type", first_rec)

    def test_quarantine_benchmark_domains_prevents_leakage(self):
        """Verifies that records belonging to quarantined domain groups are excluded from curated output."""
        records = [
            LabeledURLRecord(url="https://google.com/", label=0, threat_type="benign", registered_domain="google.com", domain_group="google.com", source="test"),
            LabeledURLRecord(url="https://docs.python.org/3/", label=0, threat_type="benign", registered_domain="python.org", domain_group="python.org", source="test"),
            LabeledURLRecord(url="https://curl.se/docs/", label=0, threat_type="benign", registered_domain="curl.se", domain_group="curl.se", source="test"),
        ]
        # Quarantine google.com and python.org (benchmark domains)
        quarantine = {"google.com", "python.org"}
        curator = DatasetCurator(quarantine_domains=quarantine)
        curated, report = curator.curate(records)

        self.assertEqual(len(curated), 1)
        self.assertEqual(curated[0].domain_group, "curl.se")
        self.assertEqual(report.quarantined_benchmark_records, 2)
        self.assertNotIn("google.com", [r.domain_group for r in curated])
        self.assertNotIn("python.org", [r.domain_group for r in curated])

    def test_structural_diversity_metrics_computation(self):
        """Verifies that structural diversity metrics (paths, hyphens, subdomains) are calculated."""
        records = [
            LabeledURLRecord(url="https://example.org/", label=0, threat_type="benign", registered_domain="example.org", domain_group="example.org", source="test"),
            LabeledURLRecord(url="https://docs.example.org/very/deep/path/resource.html", label=0, threat_type="benign", registered_domain="example.org", domain_group="example.org", source="test"),
            LabeledURLRecord(url="https://phish-login.bad-site.com/auth/verify?session=1", label=1, threat_type="phishing", registered_domain="bad-site.com", domain_group="bad-site.com", source="test"),
        ]
        curator = DatasetCurator()
        curated, report = curator.curate(records)

        self.assertIsNotNone(report.structural_diversity)
        sd = report.structural_diversity
        self.assertEqual(sd["root_only_count"], 1)
        self.assertEqual(sd["deep_path_count"], 1)
        self.assertEqual(sd["query_heavy_count"], 1)
        self.assertGreater(sd["benign_mean_path_length"], 0.0)
        self.assertGreater(sd["phishing_mean_path_length"], 0.0)


if __name__ == "__main__":
    unittest.main()

