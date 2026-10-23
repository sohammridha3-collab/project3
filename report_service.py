"""
PDF Report Generation Service for ScamShield AI
Generates downloadable, executive-ready cybersecurity audit reports using ReportLab.
"""

import io
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


def generate_scan_pdf_report(
    scan_data: Dict[str, Any],
    report_id: Optional[str] = None,
    user_name: Optional[str] = None
) -> bytes:
    """
    Constructs a styled PDF cybersecurity analysis report in memory and returns raw bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0B1220")
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748B")
    )
    h2_style = ParagraphStyle(
        "SectionH2",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0B1220"),
        spaceBefore=10,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1E293B")
    )
    mono_style = ParagraphStyle(
        "MonoText",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#0F172A")
    )
    disclaimer_style = ParagraphStyle(
        "Disclaimer",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#64748B"),
        alignment=TA_CENTER
    )

    story = []

    # 1. Header with branding
    rep_num = report_id or f"SCAN-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    header_table_data = [
        [
            Paragraph("🛡️ <b>ScamShield AI</b><br/><font size=8 color='#64748B'>Intelligent Scam Message Detection System</font>", title_style),
            Paragraph(f"<b>Report ID:</b> {rep_num}<br/><b>Date:</b> {now_str}<br/><b>Auditor:</b> {user_name or 'Public Scan'}", ParagraphStyle("HdrRight", parent=subtitle_style, alignment=TA_RIGHT))
        ]
    ]
    header_table = Table(header_table_data, colWidths=[320, 212])
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#3B82F6"), spaceAfter=14))

    # 2. Executive Verdict Banner
    is_scam = scan_data.get("is_scam", False)
    pred_class = scan_data.get("predicted_class", "Scam / Suspicious" if is_scam else "Legitimate / Ham")
    conf_pct = scan_data.get("confidence_percentage", "N/A")
    margin_val = scan_data.get("decision_margin")
    risk_level = scan_data.get("risk_level", "HIGH_RISK" if is_scam else "SAFE_LEGITIMATE")

    banner_bg = colors.HexColor("#FEF2F2") if is_scam else colors.HexColor("#F0FDF4")
    banner_border = colors.HexColor("#EF4444") if is_scam else colors.HexColor("#10B981")
    banner_text_color = "#B91C1C" if is_scam else "#047857"

    verdict_text = (
        f"<font size=14 color='{banner_text_color}'><b>VERDICT: {pred_class.upper()}</b></font><br/>"
        f"<font size=9 color='#475569'>Threat Rating: <b>{risk_level}</b> | Model Score: <b>{conf_pct}</b> "
        f"| Decision Margin: <b>{margin_val if margin_val is not None else 'N/A'}</b></font>"
    )

    verdict_table = Table([[Paragraph(verdict_text, body_style)]], colWidths=[532])
    verdict_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), banner_bg),
        ("BOX", (0, 0), (-1, -1), 1.5, banner_border),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 14))

    # 3. Technical Parameters Table
    story.append(Paragraph("Machine Learning Evaluation Parameters", h2_style))
    param_data = [
        ["Classification Engine", "LinearSVC (Linear Support Vector Classifier)"],
        ["Feature Extractors", "FeatureUnion: Word TF-IDF (80k) + Char TF-IDF (40k)"],
        ["Numerical Class Label", str(scan_data.get("predicted_label", 1 if is_scam else 0))],
        ["Calibrated Score", f"{conf_pct} (Sigmoid transformation of decision margin)"],
        ["Decision Margin (z)", f"{margin_val if margin_val is not None else 'N/A'}"],
        ["Evaluated Character Count", f"{scan_data.get('character_count', len(scan_data.get('text_preview', '')))} chars"]
    ]
    param_table = Table(param_data, colWidths=[180, 352])
    param_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0B1220")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(param_table)
    story.append(Spacer(1, 14))

    # 4. Detected Indicators & Warnings
    story.append(Paragraph("Heuristic Indicators & Anomaly Detection", h2_style))
    indicators = scan_data.get("indicators_detected", [])
    if indicators:
        ind_items = "<br/>".join([f"• <b>{ind}</b>: Pattern matching suspicious communication cues." for ind in indicators])
    else:
        ind_items = "• <b>No specific heuristic flags detected</b>. Pattern reflects neutral or standard conversational characteristics."

    ind_table = Table([[Paragraph(ind_items, body_style)]], colWidths=[532])
    ind_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFFBEB")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#FCD34D")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(ind_table)
    story.append(Spacer(1, 14))

    # 5. Evaluated Message Sample (Redacted / Safe Preview)
    story.append(Paragraph("Evaluated Message Content (Preview)", h2_style))
    raw_preview = scan_data.get("text_preview") or scan_data.get("message_text") or "No content recorded."
    # Sanitize for Platypus XML parser
    clean_preview = raw_preview.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    if len(clean_preview) > 400:
        clean_preview = clean_preview[:400] + " ... [TRUNCATED FOR SECURITY]"

    msg_table = Table([[Paragraph(clean_preview, mono_style)]], colWidths=[532])
    msg_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(msg_table)
    story.append(Spacer(1, 14))

    # 6. Safety Recommendations
    story.append(Paragraph("Recommended Cybersecurity Response", h2_style))
    if is_scam:
        recs = [
            "1. <b>Do NOT click any hyperlinks</b> or short links embedded in the message.",
            "2. <b>Never disclose passwords, OTPs, or financial details</b> in response to unverified requests.",
            "3. <b>Verify independently</b> by contacting the official institution directly via their verified website or phone.",
            "4. <b>Block and report</b> the sender phone number / email address to your telecom provider and security admin."
        ]
    else:
        recs = [
            "1. <b>Standard vigilance:</b> While not flagged as scam, always verify unexpected attachment requests.",
            "2. <b>Check sender address:</b> Ensure the sender email domain exactly matches the expected corporate or personal contact.",
            "3. <b>Follow zero-trust principles:</b> Never authenticate credentials on external, unverified portals."
        ]
    story.append(Paragraph("<br/>".join(recs), body_style))
    story.append(Spacer(1, 18))

    # 7. Disclaimer
    disclaimer_text = (
        "<b>LEGAL & ACADEMIC DISCLAIMER:</b> This report is generated by ScamShield AI (B.Tech CSE Project). "
        "Classification is performed by a machine learning model and represents an empirical statistical estimate. "
        "It does not constitute legal or forensic certification. Users must exercise due diligence before taking financial or security actions."
    )
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8))
    story.append(Paragraph(disclaimer_text, disclaimer_style))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes


def generate_call_pdf_report(
    call_data: Dict[str, Any],
    report_id: Optional[str] = None,
    user_name: Optional[str] = None
) -> bytes:
    """
    Constructs a dedicated CallScam audio analysis PDF audit report and returns raw bytes.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CallReportTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0B1220")
    )
    subtitle_style = ParagraphStyle(
        "CallReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748B")
    )
    h2_style = ParagraphStyle(
        "CallH2",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0F172A"),
        spaceBefore=10,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        "CallBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=14,
        textColor=colors.HexColor("#334155")
    )
    mono_style = ParagraphStyle(
        "CallMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#0F172A")
    )
    verdict_style = ParagraphStyle(
        "CallVerdict",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        alignment=TA_CENTER
    )
    disclaimer_style = ParagraphStyle(
        "CallDisclaimer",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=7.5,
        leading=11,
        textColor=colors.HexColor("#64748B"),
        alignment=TA_CENTER
    )

    story = []

    # 1. Header
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    rep_id = report_id or f"CALL-{int(datetime.now(timezone.utc).timestamp())}"
    header_data = [
        [
            Paragraph("🛡️ <b>ScamShield AI — CallScam Audit</b>", title_style),
            Paragraph(f"<b>Report ID:</b> #{rep_id}<br/><b>Date:</b> {now_str}", subtitle_style)
        ]
    ]
    header_table = Table(header_data, colWidths=[360, 172])
    header_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#06B6D4"), spaceAfter=14))

    # 2. Verdict Banner
    is_scam = bool(call_data.get("is_scam", False))
    if is_scam:
        v_bg = colors.HexColor("#FEF2F2")
        v_border = colors.HexColor("#EF4444")
        v_text_color = colors.HexColor("#991B1B")
        verdict_text = "🚨 POTENTIAL SCAM / MALICIOUS CALL DETECTED"
    else:
        v_bg = colors.HexColor("#F0FDF4")
        v_border = colors.HexColor("#10B981")
        v_text_color = colors.HexColor("#065F46")
        verdict_text = "✅ CALL RECORDING NOT FLAGGED AS SCAM"

    verdict_style.textColor = v_text_color
    v_table = Table([[Paragraph(verdict_text, verdict_style)]], colWidths=[532])
    v_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), v_bg),
        ("BOX", (0, 0), (-1, -1), 1.5, v_border),
        ("TOPPADDING", (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(v_table)
    story.append(Spacer(1, 14))

    # 3. Audio & Model Metadata Table
    story.append(Paragraph("Audio Call Intelligence & Model Parameters", h2_style))
    lang_name = call_data.get("language_name", "English")
    dur = call_data.get("duration_seconds")
    dur_str = f"{dur}s" if dur else "N/A"
    conf_pct = call_data.get("confidence_percentage", "N/A")

    meta_rows = [
        ["Audio Recording Filename", str(call_data.get("audio_filename", "call_recording.wav"))],
        ["Transcribed Language", f"{lang_name} ({call_data.get('detected_language', 'en').upper()})"],
        ["Audio Duration", dur_str],
        ["Confidence Score", conf_pct],
        ["Assessed Risk Category", str(call_data.get("risk_level", "LOW_RISK")).replace("_", " ")],
        ["Classification Pipeline", "SpeechRecognition (Multilingual STT) + LinearSVC / Heuristics"]
    ]
    if user_name:
        meta_rows.append(["Audited Account", user_name])

    meta_table = Table(meta_rows, colWidths=[180, 352])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#1E293B")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # 4. Transcribed Call Preview
    story.append(Paragraph("Transcribed Audio Conversation", h2_style))
    raw_transcript = call_data.get("transcript") or "No transcription available."
    clean_transcript = raw_transcript.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    if len(clean_transcript) > 600:
        clean_transcript = clean_transcript[:600] + " ... [TRUNCATED FOR REPORT]"

    trans_table = Table([[Paragraph(clean_transcript, mono_style)]], colWidths=[532])
    trans_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(trans_table)
    story.append(Spacer(1, 14))

    # 5. Warning Indicators
    indicators = call_data.get("indicators_detected", [])
    story.append(Paragraph("Explainable Fraud Indicators Detected", h2_style))
    if indicators:
        ind_items = [[Paragraph(f"⚠️ <b>{ind}</b>", body_style)] for ind in indicators]
    else:
        ind_items = [[Paragraph("No specific high-threat heuristic indicators detected.", body_style)]]
    ind_table = Table(ind_items, colWidths=[532])
    ind_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(ind_table)
    story.append(Spacer(1, 14))

    # 6. Safety Guidance
    story.append(Paragraph("Voice Security Recommendations", h2_style))
    recs = call_data.get("safety_recommendations", [])
    if not recs:
        recs = [
            "1. Never disclose one-time passwords (OTP) or banking credentials over the phone.",
            "2. Hang up and contact official customer care if threats of arrest or account locks were made.",
            "3. Do not install remote desktop apps (AnyDesk, TeamViewer) at caller instruction."
        ]
    story.append(Paragraph("<br/>".join(recs[:4]), body_style))
    story.append(Spacer(1, 16))

    # 7. Legal Disclaimer
    disclaimer_text = (
        "<b>CALLSCAM RECORDING & LEGAL DISCLAIMER:</b> This audit report is generated by ScamShield AI (B.Tech CSE Project). "
        "Classification is performed via speech-to-text transcription and machine learning text classification. "
        "Audio analysis does not certify caller caller-ID authenticity and does not replace official law enforcement investigation."
    )
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8))
    story.append(Paragraph(disclaimer_text, disclaimer_style))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes

