"""
Automated Test Suite for ScamShield AI Full-Stack System
Verifies ML Inference, Auth, History, Isolation, PDF Generation, and Static Assets.
"""

import unittest
from fastapi.testclient import TestClient
from main import app


class TestScamShieldFullStack(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client_context = TestClient(app)
        cls.client = cls.client_context.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.client_context.__exit__(None, None, None)

    def test_01_static_pages_available(self):
        """Verify HTML pages and stylesheets serve 200 OK."""
        pages = [
            "/",
            "/index.html",
            "/analyze.html",
            "/details.html",
            "/callscam.html",
            "/how-it-works.html",
            "/model-performance.html",
            "/about.html",
            "/login.html",
            "/register.html",
            "/dashboard.html",
            "/history.html",
            "/results.html",
            "/style.css"
        ]
        for p in pages:
            res = self.client.get(p)
            self.assertEqual(res.status_code, 200, f"Page {p} returned status {res.status_code}")

    def test_02_health_and_model_specs(self):
        """Verify health check and model metadata."""
        res_h = self.client.get("/health")
        self.assertEqual(res_h.status_code, 200)
        self.assertTrue(res_h.json()["model_loaded"])

        res_m = self.client.get("/model/metrics")
        self.assertEqual(res_m.status_code, 200)
        self.assertIn("heldout_test_metrics", res_m.json())
        self.assertGreater(res_m.json()["heldout_test_metrics"]["accuracy"], 0.95)

    def test_03_registration_and_login_flow(self):
        """Verify real user registration, duplicate prevention, and login with token."""
        test_email = f"student_test_{self.__class__.__name__.lower()}@university.edu"
        reg_payload = {
            "full_name": "Test Student",
            "email": test_email,
            "password": "SecurePassword123!",
            "confirm_password": "SecurePassword123!"
        }
        res_reg = self.client.post("/api/auth/register", json=reg_payload)
        # Should succeed or already exist
        if res_reg.status_code == 200:
            token = res_reg.json()["access_token"]
            self.assertIsNotNone(token)
            self.assertEqual(res_reg.json()["user"]["email"], test_email)

            # Prevent duplicate registration
            dup_res = self.client.post("/api/auth/register", json=reg_payload)
            self.assertEqual(dup_res.status_code, 400)

        # Login with correct password
        login_res = self.client.post("/api/auth/login", json={
            "email": test_email,
            "password": "SecurePassword123!"
        })
        self.assertEqual(login_res.status_code, 200)
        token = login_res.json()["access_token"]

        # Login with wrong password
        bad_login = self.client.post("/api/auth/login", json={
            "email": test_email,
            "password": "WrongPassword!"
        })
        self.assertEqual(bad_login.status_code, 401)

        # Profile check
        me_res = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        self.assertEqual(me_res.status_code, 200)
        self.assertEqual(me_res.json()["email"], test_email)

    def test_04_authenticated_predict_and_history(self):
        """Verify inference creates database record and appears in user history."""
        # 1. Login user
        test_email = f"history_test_{self.__class__.__name__.lower()}@university.edu"
        self.client.post("/api/auth/register", json={
            "full_name": "History Auditor",
            "email": test_email,
            "password": "AuditPassword123!",
            "confirm_password": "AuditPassword123!"
        })
        login_res = self.client.post("/api/auth/login", json={
            "email": test_email,
            "password": "AuditPassword123!"
        })
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Predict scam message
        pred_scam = self.client.post("/predict", json={
            "text": "CRITICAL ALERT: Your bank account is locked. Confirm your password at http://fake-login-portal.com immediately."
        }, headers=headers)
        self.assertEqual(pred_scam.status_code, 200)
        self.assertTrue(pred_scam.json()["is_scam"])
        scan_id = pred_scam.json()["scan_id"]
        self.assertIsNotNone(scan_id)

        # 3. Predict legitimate message
        pred_clean = self.client.post("/predict", json={
            "subject": "Quarterly Plan Review",
            "body": "Hi team, please find attached the slides for tomorrow's review meeting."
        }, headers=headers)
        self.assertEqual(pred_clean.status_code, 200)
        self.assertFalse(pred_clean.json()["is_scam"])

        # 4. Check stats endpoint
        stats_res = self.client.get("/api/scans/stats", headers=headers)
        self.assertEqual(stats_res.status_code, 200)
        stats = stats_res.json()
        self.assertGreaterEqual(stats["total_scans"], 2)
        self.assertGreaterEqual(stats["scam_count"], 1)
        self.assertGreaterEqual(stats["legitimate_count"], 1)

        # 5. Check history list and filter
        hist_all = self.client.get("/api/scans/history?filter_type=all", headers=headers)
        self.assertEqual(hist_all.status_code, 200)
        self.assertGreaterEqual(len(hist_all.json()), 2)

        hist_scam = self.client.get("/api/scans/history?filter_type=scam", headers=headers)
        self.assertEqual(hist_scam.status_code, 200)
        for r in hist_scam.json():
            self.assertTrue(r["is_scam"])

        # 6. Download PDF Report for the scan
        pdf_res = self.client.get(f"/api/scans/{scan_id}/report.pdf", headers=headers)
        self.assertEqual(pdf_res.status_code, 200)
        self.assertEqual(pdf_res.headers["content-type"], "application/pdf")
        self.assertGreater(len(pdf_res.content), 1000)

        # 7. Delete individual scan
        del_res = self.client.delete(f"/api/scans/{scan_id}", headers=headers)
        self.assertEqual(del_res.status_code, 200)

        # 8. Clear all history
        clear_res = self.client.delete("/api/scans/clear-all", headers=headers)
        self.assertEqual(clear_res.status_code, 200)

        empty_stats = self.client.get("/api/scans/stats", headers=headers)
        self.assertEqual(empty_stats.json()["total_scans"], 0)

    def test_05_custom_pdf_report_download(self):
        """Verify on-the-fly custom PDF generation for guest or arbitrary analysis."""
        payload = {
            "is_scam": True,
            "predicted_label": 1,
            "predicted_class": "Scam / Suspicious",
            "confidence": 0.85,
            "confidence_percentage": "85.0%",
            "decision_margin": 1.734,
            "risk_level": "HIGH_RISK",
            "indicators_detected": ["Urgency / Threat", "Suspicious URL / Shortener"],
            "text_preview": "URGENT: Click http://bit.ly/bank to unlock your account.",
            "character_count": 52
        }
        res = self.client.post("/api/report/download", json=payload)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers["content-type"], "application/pdf")
        self.assertGreater(len(res.content), 1000)

    def test_06_json_decoding_and_alternative_field_names(self):
        """Verify handling of alternative field names (text, message, msg) and malformed JSON payloads."""
        # 1. Alternative field 'message'
        res_msg = self.client.post("/predict", json={
            "message": "URGENT: Your account has been suspended. Click here to verify."
        })
        self.assertEqual(res_msg.status_code, 200)
        self.assertTrue(res_msg.json()["is_scam"])

        # 2. Alternative field 'msg'
        res_short = self.client.post("/predict", json={
            "msg": "Hello professor, attached is my assignment submission."
        })
        self.assertEqual(res_short.status_code, 200)

        # 3. Malformed JSON payload (e.g. unstringified [object Object])
        res_malformed = self.client.post(
            "/predict",
            content="[object Object]",
            headers={"Content-Type": "application/json"}
        )
        self.assertEqual(res_malformed.status_code, 422)
        self.assertIn("Invalid JSON", res_malformed.json()["detail"])

        # 4. Empty JSON payload
        res_empty = self.client.post("/predict", json={})
        self.assertEqual(res_empty.status_code, 422)

    def test_07_details_and_callscam_pages(self):
        """Verify unified Details page and CallScam page contents and structure."""
        # 1. Details page contains all required consolidated sections
        res_d = self.client.get("/details.html")
        self.assertEqual(res_d.status_code, 200)
        content_d = res_d.text
        self.assertIn("Project Overview", content_d)
        self.assertIn("How the System Works", content_d)
        self.assertIn("Model Performance", content_d)
        self.assertIn("CallScam", content_d)
        self.assertIn("Technologies Used", content_d)
        self.assertIn("Privacy, Safety & Limitations", content_d)
        self.assertIn("99.85%", content_d)

        # 2. CallScam page contains audio dropzone and microphone controls
        res_c = self.client.get("/callscam.html")
        self.assertEqual(res_c.status_code, 200)
        content_c = res_c.text
        self.assertIn("CallScam", content_c)
        self.assertIn("btn-start-record", content_c)
        self.assertIn("btn-stop-record", content_c)
        self.assertIn("btn-analyze-call", content_c)
        self.assertIn("Legal Consent", content_c)

    def test_08_multilingual_fraud_indicators_and_heuristics(self):
        """Verify multilingual script detection, regex fraud patterns, and localized advice for EN, HI, BN."""
        from call_service import detect_script_language, scan_multilingual_indicators, get_localized_safety_recommendations

        # 1. English
        en_text = "URGENT: Your bank account is locked. Provide your OTP immediately or police warrant will be issued."
        lang_code, lang_name = detect_script_language(en_text)
        self.assertEqual(lang_code, "en")
        indicators_en = scan_multilingual_indicators(en_text, "en")
        self.assertTrue(any("Urgent" in ind for ind in indicators_en))
        self.assertTrue(any("Credential" in ind or "OTP" in ind for ind in indicators_en))
        advice_en = get_localized_safety_recommendations(True, "en")
        self.assertGreater(len(advice_en), 2)

        # 2. Hindi (हिन्दी)
        hi_text = "आपका बैंक खाता तुरंत ब्लॉक कर दिया जाएगा। अपना ओटीपी और पिन तुरंत बताएं नहीं तो पुलिस गिरफ्तार करेगी।"
        lang_code, lang_name = detect_script_language(hi_text)
        self.assertEqual(lang_code, "hi")
        indicators_hi = scan_multilingual_indicators(hi_text, "hi")
        self.assertTrue(any("Urgent" in ind for ind in indicators_hi))
        self.assertTrue(any("Credential" in ind or "OTP" in ind for ind in indicators_hi))
        advice_hi = get_localized_safety_recommendations(True, "hi")
        self.assertGreater(len(advice_hi), 2)
        self.assertTrue(any("ओटीपी" in item or "बैंक" in item for item in advice_hi))

        # 3. Bengali (বাংলা)
        bn_text = "আপনার ব্যাঙ্ক অ্যাকাউন্ট এখনই বন্ধ হয়ে যাবে। ওটিপি এবং পিন নম্বর জানান নইলে পুলিশ গ্রেফতার করবে।"
        lang_code, lang_name = detect_script_language(bn_text)
        self.assertEqual(lang_code, "bn")
        indicators_bn = scan_multilingual_indicators(bn_text, "bn")
        self.assertTrue(any("Urgent" in ind for ind in indicators_bn))
        self.assertTrue(any("Credential" in ind or "OTP" in ind for ind in indicators_bn))
        advice_bn = get_localized_safety_recommendations(True, "bn")
        self.assertGreater(len(advice_bn), 2)
        self.assertTrue(any("ওটিপি" in item or "ব্যাঙ্ক" in item for item in advice_bn))

    @staticmethod
    def create_mock_wav_bytes(duration_sec=1.0):
        import io
        import wave
        import struct
        bio = io.BytesIO()
        sample_rate = 16000
        num_samples = int(sample_rate * duration_sec)
        with wave.open(bio, 'wb') as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(sample_rate)
            data = struct.pack(f'<{num_samples}h', *([0] * num_samples))
            wf.writeframes(data)
        return bio.getvalue()

    def test_09_callscam_api_endpoint_flow(self):
        """Verify CallScam API audio upload, validation, mock STT inference, and report download."""
        from unittest.mock import patch

        wav_bytes = self.create_mock_wav_bytes(duration_sec=1.0)


        # 1. Test invalid file rejection (empty audio)
        res_empty = self.client.post(
            "/api/callscam/analyze",
            files={"file": ("test.wav", b"", "audio/wav")},
            data={"language_hint": "auto"}
        )
        self.assertEqual(res_empty.status_code, 422)
        self.assertIn("Audio file is empty", res_empty.json()["detail"])

        # 2. Test mock transcription for Hindi scam call
        mock_transcript = "आपका बैंक खाता तुरंत बंद हो जाएगा। अपना ओटीपी बताएं।"
        with patch("call_service.transcribe_audio_file", return_value=(mock_transcript, "hi", "Hindi (हिन्दी)")):
            res_hi = self.client.post(
                "/api/callscam/analyze",
                files={"file": ("sample_hindi.wav", wav_bytes, "audio/wav")},
                data={"language_hint": "hi"}
            )
            self.assertEqual(res_hi.status_code, 200)
            hi_data = res_hi.json()
            self.assertTrue(hi_data["is_scam"])
            self.assertEqual(hi_data["detected_language"], "hi")
            self.assertIn("ओटीपी", hi_data["transcript"])
            self.assertGreater(len(hi_data["indicators_detected"]), 0)

        # 3. Test CallScam custom PDF generation
        pdf_payload = {
            "is_scam": True,
            "predicted_class": "Potential Scam / Social Engineering",
            "confidence": 0.92,
            "confidence_percentage": "92.0%",
            "risk_level": "HIGH_RISK",
            "detected_language": "hi",
            "language_name": "Hindi (हिन्दी)",
            "transcript": mock_transcript,
            "indicators_detected": ["Urgent Coercion / Legal Threat", "Sensitive Credential / OTP Request"],
            "safety_recommendations": ["Do not share OTP.", "Disconnect immediately."],
            "duration_seconds": 3.5,
            "audio_filename": "sample_hindi.wav"
        }
        res_pdf = self.client.post("/api/callscam/report/download", json=pdf_payload)
        self.assertEqual(res_pdf.status_code, 200)
        self.assertEqual(res_pdf.headers["content-type"], "application/pdf")
        self.assertGreater(len(res_pdf.content), 1000)

    def test_10_callscam_history_persistence_and_utc_timestamps(self):
        """Verify Bug 3 (UTC 'Z' timestamps) and Bug 4 (CallScam audio persistence in History & Stats)."""
        # 1. Register & Login a dedicated test auditor with a fresh unique email
        import uuid
        user_email = f"auditor_{uuid.uuid4().hex[:8]}@university.edu"
        reg_res = self.client.post("/api/auth/register", json={
            "full_name": "Audio Audit Specialist",
            "email": user_email,
            "password": "AuditPass123!",
            "confirm_password": "AuditPass123!"
        })
        self.assertEqual(reg_res.status_code, 200)
        login_res = self.client.post("/api/auth/login", json={
            "email": user_email,
            "password": "AuditPass123!"
        })

        self.assertEqual(login_res.status_code, 200)
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Verify UserResponse created_at has trailing 'Z'
        self.assertTrue(login_res.json()["user"]["created_at"].endswith("Z"))

        # 2. Perform authenticated message scan
        msg_res = self.client.post(
            "/predict",
            json={"text": "URGENT: Suspicious activity on your debit card. Call fraud department immediately."},
            headers=headers
        )
        self.assertEqual(msg_res.status_code, 200)
        msg_id = msg_res.json()["scan_id"]
        self.assertIsNotNone(msg_id)

        # 3. Perform authenticated call scan
        from unittest.mock import patch
        wav_bytes = self.create_mock_wav_bytes(duration_sec=3.0)
        mock_transcript = "यह क्राइम ब्रांच से वारंट है। अपना आधार नंबर बताएं।"
        with patch("call_service.transcribe_audio_file", return_value=(mock_transcript, "hi", "Hindi (हिन्दी)")):

            call_res = self.client.post(
                "/api/callscam/analyze",
                files={"file": ("police_call.wav", wav_bytes, "audio/wav")},
                data={"language_hint": "hi"},
                headers=headers
            )
            self.assertEqual(call_res.status_code, 200)
            call_data = call_res.json()
            call_id = call_data["id"]
            self.assertIsNotNone(call_id)
            self.assertTrue(call_data["created_at"].endswith("Z"))

        # 4. Verify combined stats
        stats_res = self.client.get("/api/scans/stats", headers=headers)
        self.assertEqual(stats_res.status_code, 200)
        stats = stats_res.json()
        self.assertEqual(stats["total_scans"], 2)
        for s in stats["recent_scans"]:
            self.assertTrue(s["created_at"].endswith("Z"))

        # 5. Verify unified history with record_type="all"
        hist_all = self.client.get("/api/scans/history?record_type=all", headers=headers)
        self.assertEqual(hist_all.status_code, 200)
        all_records = hist_all.json()
        self.assertEqual(len(all_records), 2)
        rec_types = {r["record_type"] for r in all_records}
        self.assertEqual(rec_types, {"message", "call"})
        for r in all_records:
            self.assertTrue(r["created_at"].endswith("Z"))

        # 6. Verify history filter record_type="message"
        hist_msg = self.client.get("/api/scans/history?record_type=message", headers=headers)
        self.assertEqual(hist_msg.status_code, 200)
        self.assertEqual(len(hist_msg.json()), 1)
        self.assertEqual(hist_msg.json()[0]["record_type"], "message")

        # 7. Verify history filter record_type="call"
        hist_call = self.client.get("/api/scans/history?record_type=call", headers=headers)
        self.assertEqual(hist_call.status_code, 200)
        self.assertEqual(len(hist_call.json()), 1)
        call_rec_item = hist_call.json()[0]
        self.assertEqual(call_rec_item["record_type"], "call")
        self.assertEqual(call_rec_item["detected_language"], "hi")
        self.assertIn("क्राइम ब्रांच", call_rec_item["message_text"])

        # 8. Verify download PDF for call scan
        call_pdf = self.client.get(f"/api/scans/{call_id}/report.pdf", headers=headers)
        self.assertEqual(call_pdf.status_code, 200)
        self.assertEqual(call_pdf.headers["content-type"], "application/pdf")
        self.assertGreater(len(call_pdf.content), 1000)

        # 9. Delete call scan
        del_res = self.client.delete(f"/api/scans/{call_id}?record_type=call", headers=headers)
        self.assertEqual(del_res.status_code, 200)

        # 10. Verify stats total drops to 1
        stats_after = self.client.get("/api/scans/stats", headers=headers)
        self.assertEqual(stats_after.json()["total_scans"], 1)

    def test_11_production_deployment_verification(self):
        """Verify production clean URLs, CORS headers for cloud origins, and deployment configs."""
        import os
        from pathlib import Path

        # 1. Verify clean URLs without .html
        clean_routes = [
            "/analyze",
            "/callscam",
            "/details",
            "/history",
            "/results",
            "/dashboard",
            "/how-it-works",
            "/model-performance",
            "/about",
            "/login",
            "/register"
        ]
        for route in clean_routes:
            res = self.client.get(route)
            self.assertEqual(res.status_code, 200, f"Clean route {route} failed with {res.status_code}")

        # 2. Verify CORS headers for cloud deployment origins
        origins_to_test = [
            "https://scamshield.onrender.com",
            "https://scamshield.vercel.app",
            "https://scamshield.netlify.app",
            "https://sohammridha3-collab.github.io"
        ]
        for origin in origins_to_test:
            res_cors = self.client.options(
                "/predict",
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "Content-Type"
                }
            )
            self.assertEqual(
                res_cors.headers.get("access-control-allow-origin"),
                origin,
                f"CORS header missing or mismatched for {origin}"
            )

        # 3. Verify deployment configuration files exist
        base_dir = Path(__file__).resolve().parent
        self.assertTrue((base_dir / "Procfile").is_file(), "Procfile must exist for PaaS deployment")
        self.assertTrue((base_dir / "render.yaml").is_file(), "render.yaml must exist for Render deployment")
        self.assertTrue((base_dir / "Dockerfile").is_file(), "Dockerfile must exist for container deployment")
        self.assertTrue((base_dir / "runtime.txt").is_file(), "runtime.txt must exist for Python version pinning")
        self.assertTrue((base_dir / ".gitignore").is_file(), ".gitignore must exist")

        # 4. Verify Procfile contains correct start command
        procfile_content = (base_dir / "Procfile").read_text(encoding="utf-8")
        self.assertIn("main:app", procfile_content)
        self.assertIn("--host 0.0.0.0", procfile_content)


if __name__ == "__main__":
    unittest.main(verbosity=2)

