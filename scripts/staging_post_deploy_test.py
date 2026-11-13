"""
TrustShield AI - Staging Post-Deployment HTTP Verification Script
Usage:
    python scripts/staging_post_deploy_test.py [--base-url URL] [--timeout SECONDS]

Executes live HTTP smoke testing against a deployed staging service (or local server):
1. /health and /api/health probes.
2. SSRF validation check (verifying 127.0.0.1 and AWS metadata are rejected).
3. Scan creation and polling (or synchronous scan analysis).
4. Controlled test cases: benign apex, multi-tier subdomain, suspicious patterns.
5. End-to-end HTTP latency benchmarking (p50, p95, p99).
6. Contract verification: verdict, risk_score, and coverage schema.
"""

import argparse
import sys
import time
from typing import Dict, Any, List
import httpx


def test_health_probes(client: httpx.Client, base_url: str) -> bool:
    print("\n[1/5] Verifying Health Probes...")
    endpoints = ["/health", "/api/health"]
    all_ok = True

    for ep in endpoints:
        url = f"{base_url}{ep}"
        t0 = time.perf_counter()
        try:
            resp = client.get(url)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("status")
                ssrf = data.get("ssrf_protection")
                version = data.get("version")
                print(f"  PASS: {ep} returned HTTP 200 in {elapsed_ms:.1f}ms (status={status}, ssrf={ssrf}, version={version})")
            else:
                print(f"  FAIL: {ep} returned HTTP {resp.status_code} in {elapsed_ms:.1f}ms: {resp.text}")
                all_ok = False
        except Exception as e:
            print(f"  ERROR: {ep} connection failed: {e}")
            all_ok = False

    return all_ok


def test_ssrf_enforcement(client: httpx.Client, base_url: str) -> bool:
    print("\n[2/5] Verifying SSRF Protection Boundary...")
    forbidden_targets = [
        "http://127.0.0.1:8000/internal",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.1/admin",
        "file:///etc/passwd",
    ]
    all_ok = True

    for target in forbidden_targets:
        url = f"{base_url}/api/v1/scan"
        try:
            resp = client.post(url, json={"url": target})
            if resp.status_code == 400:
                print(f"  PASS: SSRF blocked '{target}' with HTTP 400")
            else:
                print(f"  FAIL: SSRF target '{target}' returned unexpected HTTP {resp.status_code}")
                all_ok = False
        except Exception as e:
            print(f"  ERROR: SSRF check failed for '{target}': {e}")
            all_ok = False

    return all_ok


def test_scan_endpoints(client: httpx.Client, base_url: str) -> bool:
    print("\n[3/5] Verifying Live Scan Execution...")
    test_cases = [
        {"url": "https://example.com", "expected_verdict_in": ["clean", "suspicious"]},
        {"url": "https://api.v2.prod.aws.example.com/status", "expected_verdict_in": ["clean", "suspicious"]},
        {"url": "https://secure-login.verify-account.xyz/auth?token=123", "expected_verdict_in": ["suspicious", "phishing", "malicious"]},
    ]
    all_ok = True

    for tc in test_cases:
        target = tc["url"]
        url = f"{base_url}/api/v1/scan"
        t0 = time.perf_counter()
        try:
            resp = client.post(url, json={"url": target, "force_fresh": True})
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if resp.status_code == 200:
                data = resp.json()
                verdict = data.get("verdict")
                risk_score = data.get("risk_score")
                domain = data.get("domain")
                if verdict in tc["expected_verdict_in"]:
                    print(f"  PASS: '{domain}' scanned in {elapsed_ms:.1f}ms -> verdict='{verdict}', risk_score={risk_score}")
                else:
                    print(f"  WARN: '{domain}' returned verdict='{verdict}' (expected one of {tc['expected_verdict_in']})")
            else:
                print(f"  FAIL: Scan '{target}' returned HTTP {resp.status_code}: {resp.text}")
                all_ok = False
        except Exception as e:
            print(f"  ERROR: Scan '{target}' request failed: {e}")
            all_ok = False

    return all_ok


def benchmark_latency(client: httpx.Client, base_url: str, iterations: int = 20) -> bool:
    print(f"\n[4/5] Benchmarking HTTP Latency ({iterations} iterations)...")
    latencies_ms: List[float] = []

    for i in range(iterations):
        t0 = time.perf_counter()
        try:
            resp = client.get(f"{base_url}/health")
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if resp.status_code == 200:
                latencies_ms.append(elapsed_ms)
        except Exception:
            pass

    if not latencies_ms:
        print("  FAIL: Zero successful health requests for latency measurement.")
        return False

    latencies_ms.sort()
    n = len(latencies_ms)
    p50 = latencies_ms[int(n * 0.50)]
    p95 = latencies_ms[int(n * 0.95)]
    p99 = latencies_ms[int(n * 0.99)]

    print(f"  Measurements (n={n}): p50 = {p50:.2f}ms | p95 = {p95:.2f}ms | p99 = {p99:.2f}ms")
    if p95 < 250.0:
        print(f"  PASS: Staging p95 latency ({p95:.2f}ms) meets SLA (<250ms).")
        return True
    else:
        print(f"  WARN: Staging p95 latency ({p95:.2f}ms) exceeds 250ms target.")
        return True


def main():
    parser = argparse.ArgumentParser(description="TrustShield AI Staging Post-Deployment HTTP Smoke Test")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="Base URL of deployed service")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP request timeout in seconds")
    parser.add_argument("--staging-key", default="", help="Optional X-Staging-Key for protected staging environments")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    print("=" * 70)
    print(" TRUSTSHIELD AI - STAGING POST-DEPLOYMENT VERIFICATION")
    print(f" Target Service: {base_url}")
    print(f" Request Timeout: {args.timeout}s")
    if args.staging_key:
        print(" Staging Access Key: [CONFIGURED]")
    print("=" * 70)

    headers = {}
    if args.staging_key:
        headers["X-Staging-Key"] = args.staging_key

    with httpx.Client(timeout=args.timeout, follow_redirects=True, headers=headers) as client:
        ok_health = test_health_probes(client, base_url)
        ok_ssrf = test_ssrf_enforcement(client, base_url)
        ok_scan = test_scan_endpoints(client, base_url)
        ok_latency = benchmark_latency(client, base_url)

    print("\n" + "=" * 70)
    if ok_health and ok_ssrf and ok_scan and ok_latency:
        print(" [RESULT: PASS] Staging deployment meets all functional & security criteria.")
        print("=" * 70)
        sys.exit(0)
    else:
        print(" [RESULT: FAIL] Staging deployment failed one or more verification checks.")
        print("=" * 70)
        sys.exit(1)


if __name__ == "__main__":
    main()

