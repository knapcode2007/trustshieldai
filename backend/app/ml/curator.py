"""
TrustShield AI - Dataset Curation & Quality Verification Pipeline
Phase 2A: Safe, reproducible URL dataset acquisition, canonicalization, conflict resolution,
and quality reporting.

Guarantees:
1. URL canonicalization without merging distinct endpoints.
2. Cross-source conflict detection (quarantines conflicting labels by default).
3. Public-suffix-aware domain grouping for partition isolation.
4. Threat-type segregation (URLhaus malware kept distinct from phishing).
5. Comprehensive dataset quality and provenance reports.
6. Offline execution with zero network crawling or URL submission.
"""

import csv
import json
import os
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from backend.app.ml.dataset_importer import DatasetImporter, LabeledURLRecord
from backend.app.ml.train import group_train_val_test_split


@dataclass
class DatasetQualityReport:
    """Detailed quality and integrity telemetry for a curated URL dataset."""
    total_raw_records: int
    unique_canonical_urls: int
    duplicate_count: int
    conflict_count: int
    retained_records: int
    sources_breakdown: Dict[str, int]
    threat_type_breakdown: Dict[str, int]
    class_distribution: Dict[str, Any]
    domain_diversity: Dict[str, Any]
    conflicts: List[Dict[str, Any]]
    structural_diversity: Optional[Dict[str, Any]] = None
    quarantined_benchmark_records: int = 0
    partition_summary: Optional[Dict[str, Any]] = None
    limitations_and_caveats: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": {
                "total_raw_records": self.total_raw_records,
                "unique_canonical_urls": self.unique_canonical_urls,
                "duplicate_count": self.duplicate_count,
                "conflict_count": self.conflict_count,
                "retained_records": self.retained_records,
                "quarantined_benchmark_records": self.quarantined_benchmark_records,
            },
            "sources_breakdown": self.sources_breakdown,
            "threat_type_breakdown": self.threat_type_breakdown,
            "class_distribution": self.class_distribution,
            "domain_diversity": self.domain_diversity,
            "structural_diversity": self.structural_diversity,
            "conflicts": self.conflicts,
            "partition_summary": self.partition_summary,
            "limitations_and_caveats": self.limitations_and_caveats,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        """Renders GitHub-Flavored Markdown summary for audit and CI artifacts."""
        lines = [
            "# TrustShield AI — Dataset Quality & Provenance Report",
            "",
            "## 1. Executive Summary",
            f"- **Raw Ingested Records:** {self.total_raw_records}",
            f"- **Unique Canonical URLs:** {self.unique_canonical_urls}",
            f"- **Duplicate URLs Deduplicated:** {self.duplicate_count}",
            f"- **Cross-Source Conflicts Detected:** {self.conflict_count}",
            f"- **Quarantined Benchmark Domain Records:** {self.quarantined_benchmark_records}",
            f"- **Final Retained Curated Records:** {self.retained_records}",
            "",
            "## 2. Source Ingestion Breakdown",
            "| Source Name | Count | Share |",
            "|:---|:---:|:---:|",
        ]
        for src, cnt in sorted(self.sources_breakdown.items(), key=lambda x: x[1], reverse=True):
            pct = (cnt / max(1, self.total_raw_records)) * 100
            lines.append(f"| `{src}` | {cnt} | {pct:.1f}% |")

        lines.extend([
            "",
            "## 3. Threat Type & Class Distribution",
            "| Threat Category | Count | Class Label |",
            "|:---|:---:|:---:|",
        ])
        for ttype, cnt in sorted(self.threat_type_breakdown.items(), key=lambda x: x[1], reverse=True):
            lbl = "1 (Malicious)" if ttype in ("phishing", "malware", "suspicious") else "0 (Benign)"
            lines.append(f"| `{ttype}` | {cnt} | {lbl} |")

        c_dist = self.class_distribution
        lines.extend([
            "",
            f"- **Benign (Class 0):** {c_dist.get('benign_count', 0)} ({c_dist.get('benign_ratio', 0.0):.1%})",
            f"- **Malicious (Class 1):** {c_dist.get('malicious_count', 0)} ({c_dist.get('malicious_ratio', 0.0):.1%})",
            f"- **Imbalance Ratio:** 1:{c_dist.get('imbalance_ratio', 1.0):.2f}",
            "",
            "## 4. Domain Diversity & Grouping",
            f"- **Unique Registered Domains:** {self.domain_diversity.get('unique_domains', 0)}",
            f"- **Mean URLs per Domain:** {self.domain_diversity.get('mean_urls_per_domain', 0.0):.2f}",
            f"- **Max URLs in Single Domain:** {self.domain_diversity.get('max_urls_per_domain', 0)}",
        ])

        if self.structural_diversity:
            sd = self.structural_diversity
            lines.extend([
                "",
                "## 5. Structural Diversity & Bias Convergence",
                f"- **Root-Only URLs:** {sd.get('root_only_count', 0)} ({sd.get('root_only_share', 0.0):.1%})",
                f"- **Deep-Path URLs (>15 chars):** {sd.get('deep_path_count', 0)} ({sd.get('deep_path_share', 0.0):.1%})",
                f"- **Query-Heavy URLs:** {sd.get('query_heavy_count', 0)} ({sd.get('query_heavy_share', 0.0):.1%})",
                f"- **Multi-Tier Subdomain URLs:** {sd.get('subdomain_count', 0)} ({sd.get('subdomain_share', 0.0):.1%})",
                f"- **Long URLs (>75 chars):** {sd.get('long_url_count', 0)} ({sd.get('long_url_share', 0.0):.1%})",
                f"- **Benign Mean Path Length:** {sd.get('benign_mean_path_length', 0.0):.2f}",
                f"- **Phishing Mean Path Length:** {sd.get('phishing_mean_path_length', 0.0):.2f}",
                f"- **Benign Mean Hyphen Count:** {sd.get('benign_mean_hyphens', 0.0):.2f}",
                f"- **Phishing Mean Hyphen Count:** {sd.get('phishing_mean_hyphens', 0.0):.2f}",
                f"- **Path Length Disparity Ratio:** {sd.get('path_length_disparity_ratio', 1.0):.2f}",
            ])

        if self.conflicts:
            lines.extend([
                "",
                "## 5. Detected Conflicts & Resolutions",
                f"Total conflicting URLs: {len(self.conflicts)}",
                "| Canonical URL | Sources | Labels | Resolution |",
                "|:---|:---:|:---:|:---:|",
            ])
            for c in self.conflicts[:10]:
                srcs = ", ".join(c.get("sources", []))
                lbls = ", ".join(str(l) for l in c.get("labels", []))
                lines.append(f"| `{c.get('url')}` | {srcs} | {lbls} | {c.get('resolution')} |")
            if len(self.conflicts) > 10:
                lines.append(f"*... and {len(self.conflicts) - 10} additional quarantined conflicts.*")

        if self.partition_summary:
            p = self.partition_summary
            lines.extend([
                "",
                "## 6. Partitioning & Leakage Prevention",
                f"- **Train Partition:** {p.get('train_count', 0)} samples ({p.get('train_domains', 0)} distinct domains)",
                f"- **Calibration Partition:** {p.get('cal_count', 0)} samples ({p.get('cal_domains', 0)} distinct domains)",
                f"- **Test Partition:** {p.get('test_count', 0)} samples ({p.get('test_domains', 0)} distinct domains)",
                f"- **Domain Overlap Detected:** {p.get('domain_overlap_detected', False)}",
                f"- **Leakage Cross-Check:** {p.get('leakage_status', 'Verified Zero Overlap')}",
            ])

        lines.extend([
            "",
            "## 7. Limitations, Provenance & Caveats",
        ])
        for limitation in self.limitations_and_caveats:
            lines.append(f"- {limitation}")

        return "\n".join(lines)


class DatasetCurator:
    """
    Curates raw URL records into an audit-ready, leakage-free dataset.
    Features:
    - URL canonicalization.
    - Exact duplicate removal across diverse feeds.
    - Contradictory label conflict detection (with quarantine policy).
    - Separation of URLhaus malware from phishing.
    - Domain cap threshold to prevent single-domain bias.
    - Quality report generation with domain diversity telemetry.
    """

    def __init__(
        self,
        conflict_policy: str = "quarantine",
        include_malware_in_binary: bool = False,
        max_urls_per_domain: Optional[int] = 50,
        quarantine_domains: Optional[Any] = None,
    ):
        """
        Args:
            conflict_policy: 'quarantine' (drop conflicts), 'prefer_malicious', 'prefer_benign', or 'error'.
            include_malware_in_binary: If False, separates URLhaus malware into a distinct test set rather
                                       than mixing it into primary phishing training data.
            max_urls_per_domain: Maximum allowed URLs from any single registered domain group.
            quarantine_domains: Set of registered domain groups (e.g. held-out benchmark domains)
                                that must be strictly quarantined from the curated corpus.
        """
        if conflict_policy not in ("quarantine", "prefer_malicious", "prefer_benign", "error"):
            raise ValueError(f"Unsupported conflict_policy '{conflict_policy}'.")

        self.conflict_policy = conflict_policy
        self.include_malware_in_binary = include_malware_in_binary
        self.max_urls_per_domain = max_urls_per_domain
        self.quarantine_domains = set(quarantine_domains) if quarantine_domains else set()
        self.malware_records: List[LabeledURLRecord] = []

    def curate(self, records: List[LabeledURLRecord]) -> Tuple[List[LabeledURLRecord], DatasetQualityReport]:
        """
        Executes the curation workflow on raw labeled records:
        1. Canonicalizes all URLs.
        2. Filters quarantined benchmark domain groups.
        3. Identifies duplicates and multi-source observations.
        4. Identifies contradictory labels (conflicts) and applies conflict_policy.
        5. Filters or segregates threat types (malware vs phishing).
        6. Enforces domain capping.
        7. Computes structural diversity telemetry and produces DatasetQualityReport.
        """
        import numpy as np
        from backend.app.ml.features import URLFeatureExtractor

        total_raw = len(records)
        sources_breakdown: Dict[str, int] = {}
        for r in records:
            sources_breakdown[r.source] = sources_breakdown.get(r.source, 0) + 1

        # 1. Canonicalize, group, and quarantine held-out benchmark domains
        url_to_records: Dict[str, List[LabeledURLRecord]] = {}
        quarantined_benchmark_records = 0

        for r in records:
            canonical = DatasetImporter.canonicalize_url(r.url)
            r.canonical_url = canonical
            r.registered_domain = DatasetImporter.extract_domain_group(canonical)
            r.domain_group = r.registered_domain

            if self.quarantine_domains and r.domain_group in self.quarantine_domains:
                quarantined_benchmark_records += 1
                continue

            url_to_records.setdefault(canonical, []).append(r)

        unique_canonical = len(url_to_records)
        duplicate_count = 0
        conflicts: List[Dict[str, Any]] = []
        resolved_records: List[LabeledURLRecord] = []

        # 2. Process duplicates and conflicts
        for canonical, group in url_to_records.items():
            if len(group) > 1:
                duplicate_count += (len(group) - 1)

            labels = set(r.label for r in group)
            sources = [r.source for r in group]
            threat_types = list(set(r.threat_type for r in group))

            # Conflict detection: different feeds labeled the exact same canonical URL with different classes
            if len(labels) > 1:
                conflict_entry = {
                    "url": canonical,
                    "sources": sources,
                    "labels": list(labels),
                    "threat_types": threat_types,
                    "resolution": self.conflict_policy,
                }
                conflicts.append(conflict_entry)

                if self.conflict_policy == "error":
                    raise ValueError(f"Dataset conflict detected on URL '{canonical}' across sources {sources}.")
                elif self.conflict_policy == "quarantine":
                    # Quarantine: drop the contested URL completely
                    continue
                elif self.conflict_policy == "prefer_malicious":
                    primary = next(r for r in group if r.label == 1)
                    primary.provenance_notes = (primary.provenance_notes or "") + " [Conflict resolved: marked malicious]"
                    resolved_records.append(primary)
                elif self.conflict_policy == "prefer_benign":
                    primary = next(r for r in group if r.label == 0)
                    primary.provenance_notes = (primary.provenance_notes or "") + " [Conflict resolved: marked benign]"
                    resolved_records.append(primary)
            else:
                # No conflict: take the record with highest confidence
                best_record = max(group, key=lambda x: (x.confidence or 0.5))
                # Merge observed sources if seen across multiple feeds
                if len(group) > 1:
                    all_sources = sorted(set(sources))
                    if len(all_sources) > 1:
                        best_record.provenance_notes = (
                            (best_record.provenance_notes or "") + f" [Observed across feeds: {', '.join(all_sources)}]"
                        )
                resolved_records.append(best_record)

        # 3. Segregate threat types (Malware vs Phishing)
        curated_candidates: List[LabeledURLRecord] = []
        self.malware_records = []

        for r in resolved_records:
            if r.threat_type == "malware":
                self.malware_records.append(r)
                if self.include_malware_in_binary:
                    curated_candidates.append(r)
            else:
                curated_candidates.append(r)

        # 4. Enforce domain capping (prevent single-domain domination)
        retained_records: List[LabeledURLRecord] = []
        domain_counts: Dict[str, int] = {}

        # Sort deterministically by canonical URL
        curated_candidates.sort(key=lambda x: (x.domain_group, x.canonical_url or x.url))

        for r in curated_candidates:
            d = r.domain_group
            current = domain_counts.get(d, 0)
            if self.max_urls_per_domain and current >= self.max_urls_per_domain:
                continue
            domain_counts[d] = current + 1
            retained_records.append(r)

        # 5. Compute quality & diversity telemetry
        threat_type_breakdown: Dict[str, int] = {}
        for r in retained_records:
            threat_type_breakdown[r.threat_type] = threat_type_breakdown.get(r.threat_type, 0) + 1

        benign_cnt = sum(1 for r in retained_records if r.label == 0)
        malicious_cnt = sum(1 for r in retained_records if r.label == 1)
        tot_retained = len(retained_records)
        imbalance = round(max(benign_cnt, malicious_cnt) / max(1, min(benign_cnt, malicious_cnt)), 2)

        unique_domains = len(domain_counts)
        mean_per_domain = round(tot_retained / max(1, unique_domains), 2)
        max_in_domain = max(domain_counts.values()) if domain_counts else 0

        top_domains = [
            {"domain": d, "count": c}
            for d, c in sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]

        # Compute structural diversity & bias metrics
        benign_paths: List[float] = []
        phish_paths: List[float] = []
        benign_hyphens: List[float] = []
        phish_hyphens: List[float] = []
        root_only_cnt = 0
        deep_path_cnt = 0
        query_heavy_cnt = 0
        subdomain_cnt = 0
        long_url_cnt = 0

        for r in retained_records:
            f = URLFeatureExtractor.extract_features(r.canonical_url or r.url)
            plen = f["path_length"]
            qlen = f["query_length"]
            ulen = f["url_length"]
            hyph = f["count_hyphens"]
            subd = f["has_subdomain"]

            if plen <= 1 and qlen == 0:
                root_only_cnt += 1
            if plen > 15:
                deep_path_cnt += 1
            if qlen > 0:
                query_heavy_cnt += 1
            if subd == 1:
                subdomain_cnt += 1
            if ulen > 75:
                long_url_cnt += 1

            if r.label == 0:
                benign_paths.append(float(plen))
                benign_hyphens.append(float(hyph))
            else:
                phish_paths.append(float(plen))
                phish_hyphens.append(float(hyph))

        b_mean_p = round(float(np.mean(benign_paths)), 2) if benign_paths else 0.0
        p_mean_p = round(float(np.mean(phish_paths)), 2) if phish_paths else 0.0
        b_mean_h = round(float(np.mean(benign_hyphens)), 2) if benign_hyphens else 0.0
        p_mean_h = round(float(np.mean(phish_hyphens)), 2) if phish_hyphens else 0.0

        structural_diversity = {
            "root_only_count": root_only_cnt,
            "root_only_share": round(root_only_cnt / max(1, tot_retained), 4),
            "deep_path_count": deep_path_cnt,
            "deep_path_share": round(deep_path_cnt / max(1, tot_retained), 4),
            "query_heavy_count": query_heavy_cnt,
            "query_heavy_share": round(query_heavy_cnt / max(1, tot_retained), 4),
            "subdomain_count": subdomain_cnt,
            "subdomain_share": round(subdomain_cnt / max(1, tot_retained), 4),
            "long_url_count": long_url_cnt,
            "long_url_share": round(long_url_cnt / max(1, tot_retained), 4),
            "benign_mean_path_length": b_mean_p,
            "phishing_mean_path_length": p_mean_p,
            "benign_mean_hyphens": b_mean_h,
            "phishing_mean_hyphens": p_mean_h,
            "path_length_disparity_ratio": round(max(b_mean_p, p_mean_p) / max(0.01, min(b_mean_p, p_mean_p)), 2) if (b_mean_p and p_mean_p) else 1.0,
        }

        limitations = [
            "Tranco list domains represent apex domain popularity; URLs on these domains are not proven benign unconditionally.",
            "URLhaus entries distribute malware payloads and are segregated from credential-harvesting phishing.",
            "OpenPhish community feed is algorithmically curated without crowd verification voting.",
            "PhishTank entries are subject to reporter community bias and submission latency.",
            "URLs are curated strictly through offline lexical parsing without network crawling or payload execution.",
        ]

        report = DatasetQualityReport(
            total_raw_records=total_raw,
            unique_canonical_urls=unique_canonical,
            duplicate_count=duplicate_count,
            conflict_count=len(conflicts),
            retained_records=tot_retained,
            sources_breakdown=sources_breakdown,
            threat_type_breakdown=threat_type_breakdown,
            class_distribution={
                "benign_count": benign_cnt,
                "benign_ratio": round(benign_cnt / max(1, tot_retained), 4),
                "malicious_count": malicious_cnt,
                "malicious_ratio": round(malicious_cnt / max(1, tot_retained), 4),
                "imbalance_ratio": imbalance,
            },
            domain_diversity={
                "unique_domains": unique_domains,
                "mean_urls_per_domain": mean_per_domain,
                "max_urls_per_domain": max_in_domain,
                "top_domains": top_domains,
            },
            conflicts=conflicts,
            structural_diversity=structural_diversity,
            quarantined_benchmark_records=quarantined_benchmark_records,
            limitations_and_caveats=limitations,
        )

        return retained_records, report

    def partition_dataset(
        self,
        records: List[LabeledURLRecord],
        val_ratio: float = 0.20,
        test_ratio: float = 0.20,
        random_seed: int = 42,
        report: Optional[DatasetQualityReport] = None,
    ) -> Tuple[List[LabeledURLRecord], List[LabeledURLRecord], List[LabeledURLRecord]]:
        """
        Partitions curated records into train, calibration, and test sets with zero domain leakage.
        Updates and returns partition summary telemetry.
        """
        train_recs, cal_recs, test_recs = group_train_val_test_split(
            records=records,
            val_ratio=val_ratio,
            test_ratio=test_ratio,
            random_seed=random_seed,
        )

        train_domains = set(r.domain_group for r in train_recs)
        cal_domains = set(r.domain_group for r in cal_recs)
        test_domains = set(r.domain_group for r in test_recs)

        overlap1 = train_domains.intersection(cal_domains)
        overlap2 = train_domains.intersection(test_domains)
        overlap3 = cal_domains.intersection(test_domains)
        total_overlap = len(overlap1) + len(overlap2) + len(overlap3)

        summary = {
            "train_count": len(train_recs),
            "cal_count": len(cal_recs),
            "test_count": len(test_recs),
            "train_domains": len(train_domains),
            "cal_domains": len(cal_domains),
            "test_domains": len(test_domains),
            "domain_overlap_count": total_overlap,
            "domain_overlap_detected": total_overlap > 0,
            "leakage_status": "Zero Domain Overlap Verified" if total_overlap == 0 else "DOMAIN LEAKAGE DETECTED",
        }

        if report:
            report.partition_summary = summary

        return train_recs, cal_recs, test_recs

    @staticmethod
    def export_dataset_csv(records: List[LabeledURLRecord], filepath: str) -> None:
        """Exports curated dataset to CSV preserving all provenance metadata."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        fieldnames = [
            "url",
            "canonical_url",
            "label",
            "threat_type",
            "original_label",
            "registered_domain",
            "domain_group",
            "source",
            "confidence",
            "collection_date",
            "provenance_notes",
        ]
        with open(filepath, mode="w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in records:
                writer.writerow({
                    "url": r.url,
                    "canonical_url": r.canonical_url or r.url,
                    "label": r.label,
                    "threat_type": r.threat_type,
                    "original_label": r.original_label or "",
                    "registered_domain": r.registered_domain,
                    "domain_group": r.domain_group,
                    "source": r.source,
                    "confidence": r.confidence if r.confidence is not None else "",
                    "collection_date": r.collection_date or r.timestamp or "",
                    "provenance_notes": r.provenance_notes or "",
                })

    @staticmethod
    def export_dataset_jsonl(records: List[LabeledURLRecord], filepath: str) -> None:
        """Exports curated dataset to JSON Lines format for scalable streaming ingestion."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, mode="w", encoding="utf-8") as f:
            for r in records:
                d = {
                    "url": r.url,
                    "canonical_url": r.canonical_url or r.url,
                    "label": r.label,
                    "threat_type": r.threat_type,
                    "original_label": r.original_label,
                    "registered_domain": r.registered_domain,
                    "domain_group": r.domain_group,
                    "source": r.source,
                    "confidence": r.confidence,
                    "collection_date": r.collection_date or r.timestamp,
                    "provenance_notes": r.provenance_notes,
                }
                f.write(json.dumps(d) + "\n")

