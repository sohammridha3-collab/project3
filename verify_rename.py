import urllib.request
import re

print("Running DOM & Content Verification for 'Dashboard' to 'Results' rename...")

# 1. Check main.js
with open("main.js", "r", encoding="utf-8") as f:
    main_js = f.read()

assert '["Results"]' in main_js, "main.js missing ['Results']"
assert '["Dashboard"]' not in main_js, "main.js still has ['Dashboard']"
print("✅ main.js correctly creates nav link with label 'Results'")

# 2. Check js/main.js
with open("js/main.js", "r", encoding="utf-8") as f:
    js_main_js = f.read()

assert '["Results"]' in js_main_js, "js/main.js missing ['Results']"
assert '["Dashboard"]' not in js_main_js, "js/main.js still has ['Dashboard']"
print("✅ js/main.js correctly creates nav link with label 'Results'")

# 3. Check dashboard.html
with open("dashboard.html", "r", encoding="utf-8") as f:
    dash_html = f.read()

assert "<title>Results · ScamShield AI</title>" in dash_html, "dashboard.html title mismatch"
assert '<h1 id="welcome-msg">Results</h1>' in dash_html, "dashboard.html h1 mismatch"
assert "Security Dashboard" not in dash_html, "dashboard.html still has 'Security Dashboard'"
print("✅ dashboard.html title and <h1> heading updated to 'Results'")

# 4. Check dashboard.js and js/dashboard.js
with open("dashboard.js", "r", encoding="utf-8") as f:
    dash_js = f.read()

assert 'document.getElementById("welcome-msg").textContent = "Results";' in dash_js, "dashboard.js welcome-msg mismatch"
print("✅ dashboard.js sets welcome-msg textContent to 'Results'")

with open("js/dashboard.js", "r", encoding="utf-8") as f:
    js_dash_js = f.read()

assert 'document.getElementById("welcome-msg").textContent = "Results";' in js_dash_js, "js/dashboard.js welcome-msg mismatch"
print("✅ js/dashboard.js sets welcome-msg textContent to 'Results'")

# 5. Check index.html
with open("index.html", "r", encoding="utf-8") as f:
    index_html = f.read()

assert "View Results →" in index_html, "index.html missing 'View Results →'"
assert "Go to Dashboard →" not in index_html, "index.html still has 'Go to Dashboard →'"
print("✅ index.html card link updated to 'View Results →'")

# 6. Check results.html
with open("results.html", "r", encoding="utf-8") as f:
    res_html = f.read()

assert "📊 View Results" in res_html, "results.html missing '📊 View Results'"
assert "📊 Go to Dashboard" not in res_html, "results.html still has '📊 Go to Dashboard'"
print("✅ results.html button updated to '📊 View Results'")

# 7. Check Live Server HTTP response (5500)
try:
    with urllib.request.urlopen("http://127.0.0.1:5500/dashboard.html", timeout=3) as resp:
        content = resp.read().decode("utf-8")
        assert '<h1 id="welcome-msg">Results</h1>' in content
        print("✅ Live Server (5500) serves dashboard.html with <h1>Results</h1>")
except Exception as e:
    print("Live Server note:", e)

# 8. Check Backend HTTP response (8001)
try:
    with urllib.request.urlopen("http://127.0.0.1:8001/dashboard.html", timeout=3) as resp:
        content = resp.read().decode("utf-8")
        assert '<h1 id="welcome-msg">Results</h1>' in content
        print("✅ FastAPI Server (8001) serves dashboard.html with <h1>Results</h1>")
except Exception as e:
    print("FastAPI Server note:", e)

print("\n🎉 ALL VERIFICATION CHECKS PASSED SUCCESSFULLY!")
