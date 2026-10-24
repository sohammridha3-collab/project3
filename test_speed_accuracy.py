import time
from url_scanner_service import scan_url, SsrfBlockError

tests = [
    ("https://www.wikipedia.org", "Legitimate HTTPS"),
    ("http://example.com:81", "Slow / packet dropping port"),
    ("http://thisdomaindoesnotexistatall99999.xyz", "Non-existent domain"),
    ("http://paypal.verification-portal.badsite.com/login", "Phishing subdomain"),
    ("https://google.com@phishing-target.xyz/auth", "Deceptive @ symbol"),
    ("https://bit.ly/example-shortener", "URL Shortener")
]

print(f"{'URL':<45} | {'Verdict':<11} | {'Score':<5} | {'Time':<8} | {'Checks'}")
print("-" * 85)

for url, desc in tests:
    t0 = time.perf_counter()
    try:
        res = scan_url(url)
        el = (time.perf_counter() - t0) * 1000
        print(f"{url[:45]:<45} | {res['classification']:<11} | {res['risk_score']:<5.1f} | {el:<6.1f}ms | {len(res['checks'])} checks")
        for chk in res['checks']:
            if chk['status'] in ('warning', 'fail', 'unavailable'):
                dur = f"({chk.get('duration_ms')}ms)" if chk.get('duration_ms') is not None else ""
                print(f"   -> [{chk['status'].upper()}] {chk['name']} {dur}: {chk['details'][:70]}")
    except Exception as e:
        el = (time.perf_counter() - t0) * 1000
        print(f"{url[:45]:<45} | EXCEPTION   | 0.0   | {el:<6.1f}ms | {e}")

print("-" * 85)
t0 = time.perf_counter()
try:
    scan_url("http://127.0.0.1:8080/admin")
    print("SSRF TEST FAILED!")
except SsrfBlockError as e:
    el = (time.perf_counter() - t0) * 1000
    print(f"SSRF 127.0.0.1 blocked in {el:.2f}ms: {e}")

try:
    scan_url("http://169.254.169.254/latest/meta-data/")
    print("METADATA SSRF TEST FAILED!")
except SsrfBlockError as e:
    el = (time.perf_counter() - t0) * 1000
    print(f"SSRF 169.254.169.254 blocked in {el:.2f}ms: {e}")
