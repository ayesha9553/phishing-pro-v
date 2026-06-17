"""Quick test script for the API."""
import requests

# Test 1: Scan phishing email
print("=" * 60)
print("TEST 1: Scanning phishing email")
print("=" * 60)

with open("tests/sample_phishing.eml", "rb") as f:
    resp = requests.post(
        "http://127.0.0.1:8000/api/scan/upload",
        files={"file": ("sample_phishing.eml", f)},
    )

data = resp.json()
print(f"Status: {resp.status_code}")
print(f"Risk Score: {data['risk_score']}")
print(f"Risk Level: {data['risk_level']}")
print(f"Findings ({len(data['findings'])}):")
for f in data["findings"]:
    print(f"  [{f['severity'].upper():>8}] {f['category']}: {f['title']}")
print(f"URLs Analyzed: {len(data['urls_analyzed'])}")

# Test 2: Scan clean email
print()
print("=" * 60)
print("TEST 2: Scanning clean email")
print("=" * 60)

with open("tests/sample_clean.eml", "rb") as f:
    resp = requests.post(
        "http://127.0.0.1:8000/api/scan/upload",
        files={"file": ("sample_clean.eml", f)},
    )

data = resp.json()
print(f"Status: {resp.status_code}")
print(f"Risk Score: {data['risk_score']}")
print(f"Risk Level: {data['risk_level']}")
print(f"Findings ({len(data['findings'])}):")
for f in data["findings"]:
    print(f"  [{f['severity'].upper():>8}] {f['category']}: {f['title']}")

# Test 3: Dashboard stats
print()
print("=" * 60)
print("TEST 3: Dashboard stats")
print("=" * 60)
resp = requests.get("http://127.0.0.1:8000/api/history/stats")
stats = resp.json()
print(f"Total Scans: {stats['total_scans']}")
print(f"Threats Detected: {stats['threats_detected']}")
print(f"Safe Emails: {stats['safe_emails']}")
print(f"Avg Risk Score: {stats['avg_risk_score']}")
print(f"Risk Breakdown: {stats['risk_breakdown']}")
