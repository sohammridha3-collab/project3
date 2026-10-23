"""
HTML & CSS Interactive Web Interface for AI-Based Scam Message Detection
Embedded dashboard served at GET / for immediate testing and B.Tech CSE presentation.
"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI-Based Scam Message Detection | FastAPI ML Backend</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: rgba(18, 24, 38, 0.75);
      --card-border: rgba(255, 255, 255, 0.08);
      --accent: #6366f1;
      --accent-glow: rgba(99, 102, 241, 0.35);
      --accent-hover: #4f46e5;
      --scam: #ef4444;
      --scam-bg: rgba(239, 68, 68, 0.12);
      --scam-border: rgba(239, 68, 68, 0.35);
      --safe: #10b981;
      --safe-bg: rgba(16, 185, 129, 0.12);
      --safe-border: rgba(16, 185, 129, 0.35);
      --warn: #f59e0b;
      --warn-bg: rgba(245, 158, 11, 0.12);
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --font: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      --mono: 'JetBrains Mono', monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background-color: var(--bg);
      background-image: 
        radial-gradient(at 10% 20%, rgba(99, 102, 241, 0.15) 0px, transparent 50%),
        radial-gradient(at 90% 80%, rgba(16, 185, 129, 0.12) 0px, transparent 50%),
        radial-gradient(at 50% 50%, rgba(239, 68, 68, 0.08) 0px, transparent 50%);
      background-attachment: fixed;
      color: var(--text);
      font-family: var(--font);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      padding: 24px 20px;
    }

    header {
      max-width: 1200px;
      margin: 0 auto 28px;
      width: 100%;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 14px;
    }

    .brand-icon {
      width: 48px;
      height: 48px;
      border-radius: 14px;
      background: linear-gradient(135deg, #6366f1, #3b82f6);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 24px;
      box-shadow: 0 8px 24px var(--accent-glow);
    }

    .brand-text h1 {
      font-size: 1.45rem;
      font-weight: 800;
      letter-spacing: -0.02em;
      background: linear-gradient(to right, #ffffff, #cbd5e1);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .brand-text p {
      font-size: 0.85rem;
      color: var(--text-muted);
      font-weight: 500;
    }

    .header-links {
      display: flex;
      gap: 12px;
      align-items: center;
    }

    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 14px;
      border-radius: 9999px;
      background: rgba(16, 185, 129, 0.12);
      border: 1px solid rgba(16, 185, 129, 0.3);
      font-size: 0.8rem;
      font-weight: 600;
      color: #34d399;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #10b981;
      box-shadow: 0 0 10px #10b981;
      animation: pulse 2s infinite;
    }

    @keyframes pulse {
      0% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.5; transform: scale(1.15); }
      100% { opacity: 1; transform: scale(1); }
    }

    .api-btn {
      padding: 8px 16px;
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--card-border);
      color: var(--text);
      text-decoration: none;
      font-size: 0.85rem;
      font-weight: 600;
      transition: all 0.2s ease;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .api-btn:hover {
      background: rgba(255, 255, 255, 0.1);
      border-color: rgba(255, 255, 255, 0.2);
    }

    main {
      max-width: 1200px;
      margin: 0 auto;
      width: 100%;
      display: grid;
      grid-template-columns: 1.25fr 1fr;
      gap: 24px;
      flex: 1;
    }

    @media (max-width: 960px) {
      main { grid-template-columns: 1fr; }
    }

    .card {
      background: var(--card-bg);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--card-border);
      border-radius: 18px;
      padding: 24px;
      box-shadow: 0 12px 36px rgba(0, 0, 0, 0.35);
      position: relative;
    }

    .card-title {
      font-size: 1.1rem;
      font-weight: 700;
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .tab-container {
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
      background: rgba(0, 0, 0, 0.3);
      padding: 4px;
      border-radius: 12px;
      border: 1px solid rgba(255, 255, 255, 0.04);
    }

    .tab-btn {
      flex: 1;
      padding: 8px 14px;
      border-radius: 8px;
      border: none;
      background: transparent;
      color: var(--text-muted);
      font-size: 0.85rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .tab-btn.active {
      background: var(--accent);
      color: #ffffff;
      box-shadow: 0 4px 14px var(--accent-glow);
    }

    .sample-chips {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 16px;
    }

    .chip {
      background: rgba(255, 255, 255, 0.04);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 6px 12px;
      font-size: 0.75rem;
      font-weight: 600;
      color: var(--text-muted);
      cursor: pointer;
      transition: all 0.15s ease;
    }

    .chip:hover {
      background: rgba(99, 102, 241, 0.15);
      border-color: rgba(99, 102, 241, 0.4);
      color: #ffffff;
    }

    .input-group {
      margin-bottom: 16px;
    }

    .input-label {
      display: block;
      font-size: 0.8rem;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 6px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    input[type="text"], textarea {
      width: 100%;
      background: rgba(0, 0, 0, 0.35);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 14px 16px;
      color: var(--text);
      font-family: inherit;
      font-size: 0.95rem;
      transition: all 0.2s ease;
      resize: vertical;
    }

    input[type="text"]:focus, textarea:focus {
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 0 3px var(--accent-glow);
    }

    .btn-primary {
      width: 100%;
      padding: 14px 20px;
      background: linear-gradient(135deg, var(--accent), #4338ca);
      border: none;
      border-radius: 12px;
      color: #ffffff;
      font-size: 0.95rem;
      font-weight: 700;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      box-shadow: 0 6px 20px var(--accent-glow);
    }

    .btn-primary:hover {
      transform: translateY(-1px);
      box-shadow: 0 8px 24px rgba(99, 102, 241, 0.5);
    }

    .btn-primary:active {
      transform: translateY(0);
    }

    .btn-primary:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none;
    }

    /* Result Panel */
    .result-placeholder {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 380px;
      color: var(--text-muted);
      text-align: center;
      border: 2px dashed rgba(255, 255, 255, 0.08);
      border-radius: 14px;
      padding: 24px;
    }

    .result-placeholder .icon {
      font-size: 48px;
      margin-bottom: 12px;
      opacity: 0.6;
    }

    .result-container {
      display: none;
      animation: fadeIn 0.3s ease;
    }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(6px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .verdict-banner {
      border-radius: 14px;
      padding: 20px;
      margin-bottom: 20px;
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .verdict-banner.scam {
      background: var(--scam-bg);
      border: 1px solid var(--scam-border);
    }

    .verdict-banner.safe {
      background: var(--safe-bg);
      border: 1px solid var(--safe-border);
    }

    .verdict-icon {
      width: 52px;
      height: 52px;
      border-radius: 14px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 26px;
      flex-shrink: 0;
    }

    .scam .verdict-icon { background: rgba(239, 68, 68, 0.2); color: #f87171; }
    .safe .verdict-icon { background: rgba(16, 185, 129, 0.2); color: #34d399; }

    .verdict-title {
      font-size: 1.25rem;
      font-weight: 800;
      letter-spacing: -0.01em;
    }

    .scam .verdict-title { color: #fca5a5; }
    .safe .verdict-title { color: #6ee7b7; }

    .verdict-subtitle {
      font-size: 0.85rem;
      color: var(--text-muted);
      margin-top: 2px;
    }

    .metrics-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin-bottom: 20px;
    }

    .metric-card {
      background: rgba(0, 0, 0, 0.25);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 14px;
    }

    .metric-label {
      font-size: 0.72rem;
      text-transform: uppercase;
      color: var(--text-muted);
      font-weight: 700;
      letter-spacing: 0.05em;
    }

    .metric-val {
      font-size: 1.35rem;
      font-weight: 800;
      font-family: var(--mono);
      margin-top: 4px;
    }

    .meter-container {
      margin-bottom: 20px;
    }

    .meter-header {
      display: flex;
      justify-content: space-between;
      font-size: 0.8rem;
      font-weight: 600;
      margin-bottom: 6px;
    }

    .meter-bar {
      height: 10px;
      background: rgba(255, 255, 255, 0.06);
      border-radius: 999px;
      overflow: hidden;
      position: relative;
    }

    .meter-fill {
      height: 100%;
      border-radius: 999px;
      transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .indicators-box {
      background: rgba(0, 0, 0, 0.25);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 14px;
      margin-bottom: 16px;
    }

    .indicators-list {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 8px;
    }

    .indicator-tag {
      background: rgba(245, 158, 11, 0.15);
      border: 1px solid rgba(245, 158, 11, 0.35);
      color: #fde68a;
      border-radius: 6px;
      padding: 4px 10px;
      font-size: 0.75rem;
      font-weight: 600;
    }

    .indicator-tag.empty {
      background: rgba(255, 255, 255, 0.04);
      border-color: var(--card-border);
      color: var(--text-muted);
    }

    /* Model specs footer */
    .specs-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 14px;
      margin-top: 24px;
      max-width: 1200px;
      margin-left: auto;
      margin-right: auto;
      width: 100%;
    }

    .spec-item {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 16px;
      font-size: 0.82rem;
    }

    .spec-item .title {
      color: var(--text-muted);
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      margin-bottom: 4px;
    }

    .spec-item .value {
      font-weight: 700;
      color: #ffffff;
      font-family: var(--mono);
    }

    footer {
      max-width: 1200px;
      margin: 32px auto 8px;
      width: 100%;
      text-align: center;
      color: var(--text-muted);
      font-size: 0.8rem;
    }

    .spinner {
      border: 2px solid rgba(255, 255, 255, 0.3);
      border-top-color: #ffffff;
      border-radius: 50%;
      width: 18px;
      height: 18px;
      animation: spin 0.8s linear infinite;
      display: none;
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <div class="brand-icon">🛡️</div>
      <div class="brand-text">
        <h1>AI Scam Message Detector</h1>
        <p>B.Tech CSE Project • FastAPI ML Inference Backend</p>
      </div>
    </div>
    <div class="header-links">
      <div class="status-badge">
        <span class="status-dot"></span>
        <span id="backend-status">Model Ready</span>
      </div>
      <a href="/docs" target="_blank" class="api-btn">📚 Swagger Docs</a>
      <a href="/redoc" target="_blank" class="api-btn">📖 ReDoc</a>
      <a href="/model/info" target="_blank" class="api-btn">⚙️ Metadata</a>
    </div>
  </header>

  <main>
    <!-- Left Column: Input Form -->
    <div class="card">
      <div class="card-title">
        <span>Message Analysis</span>
        <span style="font-size: 0.8rem; color: var(--text-muted); font-weight: normal;">TF-IDF + LinearSVC</span>
      </div>

      <div class="tab-container">
        <button class="tab-btn active" id="tab-text" onclick="switchMode('text')">Direct Text / SMS</button>
        <button class="tab-btn" id="tab-email" onclick="switchMode('email')">Structured Email</button>
        <button class="tab-btn" id="tab-batch" onclick="switchMode('batch')">Batch Test</button>
      </div>

      <!-- Quick Preset Samples -->
      <div class="sample-chips" id="sample-chips">
        <span class="chip" onclick="loadSample('bank')">🚨 Bank Phishing</span>
        <span class="chip" onclick="loadSample('lottery')">🎁 Lottery Lure</span>
        <span class="chip" onclick="loadSample('work')">💼 Meeting Sync (Ham)</span>
        <span class="chip" onclick="loadSample('sms')">💬 Casual SMS (Ham)</span>
      </div>

      <!-- Single Direct Text Input -->
      <div id="mode-text">
        <div class="input-group">
          <label class="input-label" for="input-text">Message / SMS Body</label>
          <textarea id="input-text" rows="8" placeholder="Paste incoming SMS or email content here for AI scam analysis..."></textarea>
        </div>
      </div>

      <!-- Structured Email Input -->
      <div id="mode-email" style="display: none;">
        <div class="input-group">
          <label class="input-label" for="input-subject">Email Subject</label>
          <input type="text" id="input-subject" placeholder="e.g. URGENT: Verify your account immediately">
        </div>
        <div class="input-group">
          <label class="input-label" for="input-body">Email Body</label>
          <textarea id="input-body" rows="6" placeholder="Dear Customer, your bank access has been locked due to suspicious activity. Click here to confirm identity..."></textarea>
        </div>
      </div>

      <!-- Batch Mode Input -->
      <div id="mode-batch" style="display: none;">
        <div class="input-group">
          <label class="input-label" for="input-batch">Multiple Messages (One per line)</label>
          <textarea id="input-batch" rows="8" placeholder="Urgent! Call this number to claim prize\nHey mom, can you pick up bread?\nYour PayPal account is suspended. Verify now\nMeeting moved to Friday 3pm"></textarea>
        </div>
      </div>

      <button class="btn-primary" id="btn-predict" onclick="runAnalysis()">
        <span class="spinner" id="loading-spinner"></span>
        <span id="btn-label">Classify with AI Pipeline</span>
      </button>
    </div>

    <!-- Right Column: Results & Explainability -->
    <div class="card">
      <div class="card-title">
        <span>Classification Verdict</span>
        <span id="latency-tag" style="font-size: 0.8rem; color: var(--text-muted); font-family: var(--mono);"></span>
      </div>

      <!-- Placeholder before first run -->
      <div class="result-placeholder" id="placeholder">
        <div class="icon">🔍</div>
        <p style="font-weight: 600; font-size: 1rem; color: var(--text);">No Message Evaluated Yet</p>
        <p style="font-size: 0.85rem; margin-top: 6px;">Select a sample preset or enter text on the left, then click <strong>Classify with AI Pipeline</strong>.</p>
      </div>

      <!-- Real-time Result Output -->
      <div class="result-container" id="result-box">
        <div class="verdict-banner" id="verdict-banner">
          <div class="verdict-icon" id="verdict-icon">⚠️</div>
          <div>
            <div class="verdict-title" id="verdict-title">Scam / Suspicious</div>
            <div class="verdict-subtitle" id="verdict-subtitle">Flagged by ML Decision Hyperplane</div>
          </div>
        </div>

        <div class="meter-container">
          <div class="meter-header">
            <span>Scam Likelihood Probability</span>
            <span id="prob-display" style="font-family: var(--mono); font-weight: 700;">94.2%</span>
          </div>
          <div class="meter-bar">
            <div class="meter-fill" id="meter-fill" style="width: 94%;"></div>
          </div>
        </div>

        <div class="metrics-grid">
          <div class="metric-card">
            <div class="metric-label">Decision Margin (z)</div>
            <div class="metric-val" id="metric-margin">+1.28</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Risk Level</div>
            <div class="metric-val" id="metric-risk">HIGH</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Predicted Label</div>
            <div class="metric-val" id="metric-label">1</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Calibration Method</div>
            <div class="metric-val" id="metric-calib" style="font-size: 1rem;">Platt Sigmoid</div>
          </div>
        </div>

        <div class="indicators-box">
          <div class="metric-label">Explainable Scam Indicators Detected</div>
          <div class="indicators-list" id="indicators-list">
            <span class="indicator-tag">Urgency Trigger</span>
            <span class="indicator-tag">Suspicious URL</span>
          </div>
        </div>
      </div>

      <!-- Batch Result Container -->
      <div class="result-container" id="batch-result-box" style="display: none; max-height: 480px; overflow-y: auto;">
        <div class="metrics-grid" style="margin-bottom: 14px;">
          <div class="metric-card">
            <div class="metric-label">Total Evaluated</div>
            <div class="metric-val" id="batch-total">0</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Scam Ratio</div>
            <div class="metric-val" id="batch-scam-ratio" style="color: #f87171;">0%</div>
          </div>
        </div>
        <div id="batch-items-list" style="display: flex; flex-direction: column; gap: 8px;"></div>
      </div>
    </div>
  </main>

  <!-- Technical Specs Cards -->
  <div class="specs-grid">
    <div class="spec-item">
      <div class="title">Trained Model</div>
      <div class="value">LinearSVC (Selected via CV)</div>
    </div>
    <div class="spec-item">
      <div class="title">Held-out Accuracy</div>
      <div class="value" style="color: #34d399;">99.85%</div>
    </div>
    <div class="spec-item">
      <div class="title">F1-Score (Label 1)</div>
      <div class="value" style="color: #34d399;">99.86%</div>
    </div>
    <div class="spec-item">
      <div class="title">Feature Space</div>
      <div class="value">Word (80k) + Char (40k) TF-IDF</div>
    </div>
    <div class="spec-item">
      <div class="title">Dataset</div>
      <div class="value">CEAS_08 (39,154 records)</div>
    </div>
  </div>

  <footer>
    AI-Based Scam Message Detection • Final B.Tech CSE Project • Built with FastAPI, scikit-learn & joblib
  </footer>

  <script>
    let activeMode = 'text';

    const SAMPLES = {
      bank: {
        subject: "SECURITY ALERT: Immediate Action Required on Your Bank Account",
        body: "Dear Customer, We have detected unusual login attempts from an unknown device. Your access has been restricted. Please click http://secure-bank-verify.fake-portal.com to confirm your password and identity within 24 hours.",
        text: "SECURITY ALERT: Unusual login detected from unknown IP. Your bank account is locked. Verify immediately at http://bit.ly/bank-security-login or funds will be frozen."
      },
      lottery: {
        subject: "Congratulations! You won the $1,000,000 Cash Sweepstakes",
        body: "You have been selected as the grand prize winner of $1,000,000 in our international lottery! Send your bank account details and wire transfer fee immediately to claim your check.",
        text: "WINNER! You have won a $1,000,000 Walmart cash gift card. Call 1-800-555-0199 now or click http://claim-prize-now.com to claim before expiration."
      },
      work: {
        subject: "Project Review Meeting - Agenda and Slide Deck",
        body: "Hi team, please find attached the presentation slides for our quarterly review meeting scheduled for tomorrow at 10:00 AM in Conference Room B. Let me know if you have additions.",
        text: "Hi John, please review the attached financial report before our sync at 3 PM today. Let me know if you have any questions."
      },
      sms: {
        subject: "Checking in",
        body: "Hey, can you pick up some milk and eggs on your way back from work? Love you!",
        text: "Hey, are we still meeting at the library at 5 PM? Let me know!"
      }
    };

    function switchMode(mode) {
      activeMode = mode;
      document.getElementById('tab-text').classList.toggle('active', mode === 'text');
      document.getElementById('tab-email').classList.toggle('active', mode === 'email');
      document.getElementById('tab-batch').classList.toggle('active', mode === 'batch');

      document.getElementById('mode-text').style.display = mode === 'text' ? 'block' : 'none';
      document.getElementById('mode-email').style.display = mode === 'email' ? 'block' : 'none';
      document.getElementById('mode-batch').style.display = mode === 'batch' ? 'block' : 'none';
      document.getElementById('sample-chips').style.display = mode === 'batch' ? 'none' : 'flex';
    }

    function loadSample(key) {
      const s = SAMPLES[key];
      if (!s) return;
      if (activeMode === 'email') {
        document.getElementById('input-subject').value = s.subject;
        document.getElementById('input-body').value = s.body;
      } else {
        document.getElementById('input-text').value = s.text;
      }
      runAnalysis();
    }

    async function runAnalysis() {
      const btn = document.getElementById('btn-predict');
      const spinner = document.getElementById('loading-spinner');
      const label = document.getElementById('btn-label');
      
      btn.disabled = true;
      spinner.style.display = 'inline-block';
      label.textContent = 'Analyzing...';

      const startTime = performance.now();

      try {
        if (activeMode === 'batch') {
          await runBatchAnalysis();
        } else {
          await runSingleAnalysis();
        }
      } catch (err) {
        alert("Prediction Error: " + (err.message || err));
      } finally {
        const elapsed = (performance.now() - startTime).toFixed(1);
        document.getElementById('latency-tag').textContent = `${elapsed} ms`;
        btn.disabled = false;
        spinner.style.display = 'none';
        label.textContent = 'Classify with AI Pipeline';
      }
    }

    async function runSingleAnalysis() {
      let payload = {};
      if (activeMode === 'email') {
        const subj = document.getElementById('input-subject').value.trim();
        const bdy = document.getElementById('input-body').value.trim();
        if (!subj && !bdy) {
          alert('Please enter an email subject or body.');
          return;
        }
        payload = { subject: subj, body: bdy, message_type: 'email' };
      } else {
        const txt = document.getElementById('input-text').value.trim();
        if (!txt) {
          alert('Please enter a message to analyze.');
          return;
        }
        payload = { text: txt, message_type: 'sms' };
      }

      const res = await fetch('/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.detail || `Server returned ${res.status}`);
      }

      const data = await res.json();
      displaySingleResult(data);
    }

    function displaySingleResult(data) {
      document.getElementById('placeholder').style.display = 'none';
      document.getElementById('batch-result-box').style.display = 'none';
      const box = document.getElementById('result-box');
      box.style.display = 'block';

      const banner = document.getElementById('verdict-banner');
      const icon = document.getElementById('verdict-icon');
      const title = document.getElementById('verdict-title');
      const subtitle = document.getElementById('verdict-subtitle');
      const fill = document.getElementById('meter-fill');
      const probText = document.getElementById('prob-display');

      banner.className = 'verdict-banner ' + (data.is_scam ? 'scam' : 'safe');
      icon.textContent = data.is_scam ? '🚨' : '✅';
      title.textContent = data.is_scam ? 'Scam / Phishing Detected' : 'Legitimate Message';
      subtitle.textContent = data.is_scam 
        ? 'High probability of fraud, phishing lure, or malicious intent'
        : 'Message appears normal and consistent with legitimate communication';

      const pct = (data.confidence * 100).toFixed(1);
      probText.textContent = `${pct}%`;
      fill.style.width = `${pct}%`;
      fill.style.background = data.is_scam 
        ? 'linear-gradient(90deg, #f59e0b, #ef4444)' 
        : 'linear-gradient(90deg, #3b82f6, #10b981)';

      document.getElementById('metric-margin').textContent = 
        data.decision_margin !== null ? (data.decision_margin > 0 ? '+' : '') + data.decision_margin : 'N/A';
      document.getElementById('metric-risk').textContent = data.risk_level.replace('_', ' ');
      document.getElementById('metric-risk').style.color = data.is_scam ? '#f87171' : '#34d399';
      document.getElementById('metric-label').textContent = data.predicted_label;
      document.getElementById('metric-calib').textContent = 
        data.score_type === 'calibrated_sigmoid' ? 'Platt Sigmoid' : data.score_type;

      // Indicators
      const list = document.getElementById('indicators-list');
      list.innerHTML = '';
      if (data.indicators_detected && data.indicators_detected.length > 0) {
        data.indicators_detected.forEach(tag => {
          const s = document.createElement('span');
          s.className = 'indicator-tag';
          s.textContent = '⚠️ ' + tag;
          list.appendChild(s);
        });
      } else {
        const s = document.createElement('span');
        s.className = 'indicator-tag empty';
        s.textContent = 'None detected (Pattern is neutral)';
        list.appendChild(s);
      }
    }

    async function runBatchAnalysis() {
      const rawLines = document.getElementById('input-batch').value.split('\\n')
        .map(l => l.trim())
        .filter(l => l.length > 0);

      if (rawLines.length === 0) {
        alert('Please enter at least one message line.');
        return;
      }

      const payload = {
        messages: rawLines.map(line => ({ text: line }))
      };

      const res = await fetch('/predict/batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.detail || `Server returned ${res.status}`);
      }

      const data = await res.json();
      displayBatchResult(data);
    }

    function displayBatchResult(data) {
      document.getElementById('placeholder').style.display = 'none';
      document.getElementById('result-box').style.display = 'none';
      const box = document.getElementById('batch-result-box');
      box.style.display = 'block';

      document.getElementById('batch-total').textContent = data.total_messages;
      document.getElementById('batch-scam-ratio').textContent = `${data.overall_scam_percentage}% (${data.scam_count} scam, ${data.legitimate_count} ham)`;

      const list = document.getElementById('batch-items-list');
      list.innerHTML = '';

      data.results.forEach((item, idx) => {
        const div = document.createElement('div');
        div.style.background = 'rgba(0,0,0,0.3)';
        div.style.border = '1px solid ' + (item.is_scam ? 'rgba(239,68,68,0.3)' : 'rgba(16,185,129,0.3)');
        div.style.borderRadius = '10px';
        div.style.padding = '10px 14px';
        div.style.display = 'flex';
        div.style.justifyContent = 'space-between';
        div.style.alignItems = 'center';

        div.innerHTML = `
          <div style="flex: 1; padding-right: 12px;">
            <div style="font-size: 0.85rem; color: #fff; font-weight: 500;">${item.text_preview}</div>
            <div style="font-size: 0.72rem; color: var(--text-muted); margin-top: 2px;">
              ${item.indicators_detected.join(' • ') || 'No heuristic indicators'}
            </div>
          </div>
          <div style="text-align: right; flex-shrink: 0;">
            <span style="display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: 700; background: ${item.is_scam ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)'}; color: ${item.is_scam ? '#f87171' : '#34d399'};">
              ${item.predicted_class} (${item.confidence_percentage})
            </span>
          </div>
        `;
        list.appendChild(div);
      });
    }

    // Health check on initial page load
    async function checkHealth() {
      try {
        const res = await fetch('/health');
        if (res.ok) {
          const data = await res.json();
          document.getElementById('backend-status').textContent = `${data.classifier} Online`;
        }
      } catch (e) {
        document.getElementById('backend-status').textContent = 'Backend Offline';
      }
    }
    checkHealth();
  </script>
</body>
</html>
"""
