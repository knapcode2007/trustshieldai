"""
TrustShield AI - Phase 8C Production Backend Integration Smoke Test
Simulates the exact API request sequence executed by the Vercel frontend
against the live production Render backend: https://trustshield-api-zsv1.onrender.com
"""

import sys
import time
import httpx

BASE_URL = "https://trustshield-api-zsv1.onrender.com"

def run_integration_test():
    print("=" * 70)
    print(" TRUSTSHIELD AI - PHASE 8C PRODUCTION BACKEND INTEGRATION AUDIT")
    print(f" Target API Gateway: {BASE_URL}")
    print("=" * 70)

    client = httpx.Client(base_url=BASE_URL, timeout=45.0)
    passes = 0
    total = 6

    # 1. Health Probe (/v1/health)
    print("\n[1/6] Testing System Health & Telemetry (/v1/health)...")
    try:
        t0 = time.perf_counter()
        r = client.get("/v1/health")
        latency = (time.perf_counter() - t0) * 1000
        if r.status_code == 200:
            data = r.json()
            db_status = data.get("subsystems", {}).get("database", {}).get("status")
            print(f"  PASS: HTTP 200 ({latency:.1f}ms) | DB: {db_status} | App: {data.get('app_name')}")
            passes += 1
        else:
            print(f"  FAIL: Expected HTTP 200, got {r.status_code}: {r.text}")
    except Exception as e:
        print(f"  ERROR: {e}")

    # 2. Legitimate URL Scan Workflow (POST /v1/scans -> poll -> GET /v1/reports/:id)
    print("\n[2/6] Testing Legitimate URL Scan (https://github.com)...")
    try:
        t0 = time.perf_counter()
        r = client.post("/v1/scans", json={"url": "https://github.com", "force_fresh": False})
        if r.status_code in (200, 202):
            scan_id = r.json().get("scan_id")
            print(f"  Job Submitted: {scan_id} (HTTP {r.status_code})")

            # Poll for completion
            completed = False
            for poll_idx in range(15):
                time.sleep(1.0)
                r_status = client.get(f"/v1/scans/{scan_id}")
                st = r_status.json().get("state")
                if st in ("completed", "partial"):
                    completed = True
                    break

            if completed:
                r_rep = client.get(f"/v1/reports/{scan_id}")
                rep_data = r_rep.json()
                verdict = rep_data.get("verdict")
                risk = rep_data.get("risk_score")
                print(f"  PASS: Scan Completed | Verdict: {verdict} | Risk: {risk}/100")
                passes += 1
            else:
                print(f"  FAIL: Scan did not complete within 15s")
        else:
            print(f"  FAIL: Scan creation failed with HTTP {r.status_code}")
    except Exception as e:
        print(f"  ERROR: {e}")

    # 3. Threat Indicator Feed (/v1/intel/indicators)
    print("\n[3/6] Testing Threat Intelligence Indicators (/v1/intel/indicators)...")
    try:
        r = client.get("/v1/intel/indicators")
        if r.status_code == 200:
            items = r.json()
            print(f"  PASS: HTTP 200 | Retrieved {len(items)} verified IOCs")
            passes += 1
        else:
            print(f"  FAIL: Expected HTTP 200, got {r.status_code}")
    except Exception as e:
        print(f"  ERROR: {e}")

    # 4. Community Reports Feed (/v1/community/reports)
    print("\n[4/6] Testing Community Reports Feed (/v1/community/reports)...")
    try:
        r = client.get("/v1/community/reports")
        if r.status_code == 200:
            items = r.json()
            print(f"  PASS: HTTP 200 | Retrieved {len(items)} crowd-sourced reports")
            passes += 1
        else:
            print(f"  FAIL: Expected HTTP 200, got {r.status_code}")
    except Exception as e:
        print(f"  ERROR: {e}")

    # 5. Continuous Watchlist (/v1/watchlist)
    print("\n[5/6] Testing Monitored Watchlist (/v1/watchlist)...")
    try:
        r = client.get("/v1/watchlist")
        if r.status_code == 200:
            items = r.json()
            print(f"  PASS: HTTP 200 | Retrieved {len(items)} monitored targets")
            passes += 1
        else:
            print(f"  FAIL: Expected HTTP 200, got {r.status_code}")
    except Exception as e:
        print(f"  ERROR: {e}")

    # 6. TLS Handshake Inspection (/v1/tls/inspect)
    print("\n[6/6] Testing Cryptographic TLS Inspector (/v1/tls/inspect)...")
    try:
        r = client.post("/v1/tls/inspect", json={"hostname": "github.com"})
        if r.status_code == 200:
            data = r.json()
            grade = data.get("certificate", {}).get("grade", "N/A")
            issuer = data.get("certificate", {}).get("issuer", "Unknown")
            print(f"  PASS: HTTP 200 | Host: github.com | Grade: {grade} | Issuer: {issuer}")
            passes += 1
        else:
            print(f"  FAIL: Expected HTTP 200, got {r.status_code}")
    except Exception as e:
        print(f"  ERROR: {e}")

    print("\n" + "=" * 70)
    print(f" INTEGRATION AUDIT SCORE: {passes}/{total} CHECKS PASSED")
    print("=" * 70)

    if passes == total:
        print(" [RESULT: PASS] Production Render backend is fully compatible with Vercel frontend.")
        sys.exit(0)
    else:
        print(" [RESULT: FAIL] Production backend integration failed one or more checks.")
        sys.exit(1)

if __name__ == "__main__":
    run_integration_test()

