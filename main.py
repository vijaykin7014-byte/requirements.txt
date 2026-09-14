import os
import re
import json
import requests
import html
import traceback
from datetime import datetime, timezone

import telebot
import google.generativeai as genai

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER

# ============================================================
# CONFIGURATION
# ============================================================

ETHERSCAN_API_KEY = "9985GCEPN4ZA4IT6TCN8JW1IRVCR82C7GA"
TELEGRAM_BOT_TOKEN = "8698387580:AAFwdL3c4N8lwJsvX5q7GUnxg3sjlynbqjU"
GEMINI_API_KEY = "AQ.Ab8RN6LdPdECVEnjxRMnZZmV2pRCWguLIkiORo5X_GrO8YHb-w" 

# Ethereum Mainnet
CHAIN_ID = "1"

bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

# Configure Gemini
genai.configure(api_key=GEMINI_API_KEY)


# ============================================================
# ADDRESS VALIDATION
# ============================================================

def valid_address(address):
    return bool(re.fullmatch(r"0x[a-fA-F0-9]{40}", address))


# ============================================================
# ETHERSCAN SOURCE
# ============================================================

def get_contract_source(address):
    url = "https://api.etherscan.io/v2/api"
    params = {
        "chainid": CHAIN_ID,
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": ETHERSCAN_API_KEY
    }

    response = requests.get(url, params=params, timeout=15) # Timeout reduced for speed
    response.raise_for_status()
    data = response.json()
    result = data.get("result")

    if not result:
        raise Exception("Etherscan returned no contract information.")

    if isinstance(result, str):
        raise Exception(f"Etherscan error: {result}")

    item = result[0]
    source = item.get("SourceCode", "")

    if not source:
        raise Exception("Contract source code is not verified on Etherscan.")

    return {
        "source": source,
        "contract_name": item.get("ContractName", "Unknown"),
        "compiler": item.get("CompilerVersion", "Unknown"),
        "optimization": item.get("OptimizationUsed", "Unknown"),
        "proxy": item.get("Proxy", "0"),
        "implementation": item.get("Implementation", "")
    }


def clean_source(source):
    if source.startswith("{{") and source.endswith("}}"):
        source = source[1:-1]
    return source


# ============================================================
# BASIC STATIC CHECKS
# ============================================================

def basic_checks(source):
    findings = []
    patterns = [
        (r"\.call\s*\{", "Low-level call detected", "Review external call handling and reentrancy protection."),
        (r"\.delegatecall\s*\(", "delegatecall detected", "Review target validation and storage-context safety."),
        (r"\btx\.origin\b", "tx.origin detected", "Avoid tx.origin for authorization."),
        (r"\bselfdestruct\s*\(", "selfdestruct detected", "Review whether destruction is intentional and protected."),
        (r"\bblock\.timestamp\b", "Block timestamp detected", "Do not rely on timestamp for security-critical randomness."),
        (r"\bassembly\s*\{", "Inline assembly detected", "Assembly requires careful manual review."),
        (r"\bupgradeTo\b", "Upgradeable contract pattern detected", "Review upgrade authorization and implementation controls."),
    ]

    for pattern, title, recommendation in patterns:
        matches = re.findall(pattern, source, flags=re.IGNORECASE)
        if matches:
            findings.append({
                "title": title,
                "evidence": f"Pattern found {len(matches)} time(s).",
                "recommendation": recommendation
            })
    return findings


# ============================================================
# GEMINI AI ANALYSIS
# ============================================================

def gemini_analysis(source, basic):
    basic_text = json.dumps(basic, indent=2)
    source_for_ai = source[:100000] # Optimized size for faster processing

    prompt = f"""
You are a defensive Web3 smart-contract security auditor.
Analyze the Solidity source code below. Return ONLY valid JSON.

Required format:
{{
  "overall_result": "NO_CLEAR_BUGS | POTENTIAL_ISSUES | VULNERABILITIES_FOUND",
  "summary": "short summary",
  "findings": [
    {{
      "title": "finding title",
      "severity": "Critical | High | Medium | Low | Informational",
      "confidence": "High | Medium | Low",
      "location": "function/contract",
      "description": "technical explanation",
      "evidence": "specific code behavior",
      "impact": "possible security impact",
      "recommendation": "safe remediation"
    }}
  ]
}}

STATIC PRE-CHECKS:
{basic_text}

SOLIDITY SOURCE:
{source_for_ai}
"""
    try:
        # Correct model name: gemini-1.5-flash is extremely fast
        model = genai.GenerativeModel(
            'gemini-3.5-flash',
            generation_config={"response_mime_type": "application/json"}
        )
        response = model.generate_content(prompt)
        text = response.text.strip()
        
        return json.loads(text)

    except Exception as e:
        print(f"Gemini Analysis Error: {e}")
        return {
            "overall_result": "UNKNOWN",
            "summary": f"AI processing failed. Error: {str(e)[:200]}",
            "findings": []
        }


# ============================================================
# PDF REPORT GENERATION
# ============================================================

def create_pdf(address, info, analysis, static_findings):
    filename = os.path.join(os.getcwd(), f"web3_audit_{address[:10]}.pdf")
    
    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    title_style.alignment = TA_CENTER
    body = styles["BodyText"]
    body.leading = 14
    heading = styles["Heading2"]

    doc = SimpleDocTemplate(filename, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    story = []

    story.append(Paragraph("Web3 Smart Contract Security Report", title_style))
    story.append(Spacer(1, 15))

    metadata = [
        ["Contract", address],
        ["Name", info["contract_name"]],
        ["Compiler", info["compiler"]],
        ["Proxy", info["proxy"]],
        ["Generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")]
    ]

    meta_table = Table(metadata, colWidths=[100, 390])
    meta_table.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("BACKGROUND", (0,0), (0,-1), colors.lightgrey),
        ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 8),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 20))

    result = analysis.get("overall_result", "UNKNOWN")
    story.append(Paragraph(f"<b>Overall Result:</b> {html.escape(result)}", body))
    story.append(Spacer(1, 10))

    summary = html.escape(str(analysis.get("summary", "No summary.")))
    story.append(Paragraph(f"<b>Summary:</b> {summary}", body))
    story.append(Spacer(1, 20))

    story.append(Paragraph("Security Findings", heading))
    findings = analysis.get("findings", [])

    if not findings:
        story.append(Paragraph("No clear vulnerabilities were identified by automated analysis.", body))

    for index, finding in enumerate(findings, 1):
        story.append(Spacer(1, 12))
        title = html.escape(str(finding.get("title", "Unknown")))
        story.append(Paragraph(f"<b>{index}. {title}</b>", body))

        fields = [
            ("Severity", "severity"),
            ("Confidence", "confidence"),
            ("Location", "location"),
            ("Description", "description"),
            ("Evidence", "evidence"),
            ("Impact", "impact"),
            ("Recommendation", "recommendation")
        ]

        rows = []
        for label, key in fields:
            value = html.escape(str(finding.get(key, "N/A")))
            rows.append([label, value])

        table = Table(rows, colWidths=[100, 390])
        table.setStyle(TableStyle([
            ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
            ("BACKGROUND", (0,0), (0,-1), colors.lightgrey),
            ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 8),
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("LEFTPADDING", (0,0), (-1,-1), 5),
            ("RIGHTPADDING", (0,0), (-1,-1), 5),
        ]))
        story.append(table)

    story.append(Spacer(1, 20))
    story.append(Paragraph("<b>Disclaimer:</b> This is an automated security-assistance report, not a formal audit.", body))

    doc.build(story)
    return filename


# ============================================================
# TELEGRAM HANDLERS
# ============================================================

@bot.message_handler(commands=["start"])
def start(message):
    bot.reply_to(
        message,
        "🤖 <b>Web3 Security Auditor (Powered by Gemini)</b>\n\n"
        "Send me a contract to audit:\n"
        "<code>/scan 0xYourContractAddress</code>\n\n"
        "I will fetch the source, run AI analysis, and generate a PDF report.",
        parse_mode="HTML"
    )

@bot.message_handler(commands=["scan"])
def scan(message):
    parts = message.text.strip().split()

    if len(parts) != 2:
        bot.reply_to(message, "❌ Correct format:\n<code>/scan 0x12345...</code>", parse_mode="HTML")
        return

    address = parts[1]
    if not valid_address(address):
        bot.reply_to(message, "❌ Invalid Ethereum address.")
        return

    status = bot.reply_to(message, "🔎 Fetching contract source from Etherscan...")
    pdf_file = None

    try:
        # 1. Fetch Source
        info = get_contract_source(address)
        source = clean_source(info["source"])
        bot.edit_message_text("🧪 Running Static security checks...", message.chat.id, status.message_id)

        # 2. Static Analysis
        static_findings = basic_checks(source)
        bot.edit_message_text("⚡ Running Ultra-Fast Gemini AI Analysis...", message.chat.id, status.message_id)

        # 3. Gemini AI Analysis
        analysis = gemini_analysis(source, static_findings)
        
        # 4. Generate PDF
        bot.edit_message_text("📑 Generating PDF Report...", message.chat.id, status.message_id)
        pdf_file = create_pdf(address, info, analysis, static_findings)
        
        result = analysis.get("overall_result", "UNKNOWN")
        summary = analysis.get("summary", "No summary.")
        findings_count = len(analysis.get("findings", []))

        # HTML Safe Formatting (Fixes Telegram Parsing Error)
        safe_name = html.escape(info['contract_name'])
        safe_result = html.escape(str(result))
        safe_summary = html.escape(str(summary)[:250]) # Extract up to 250 characters securely

        message_text = (
            f"✅ <b>AUDIT COMPLETE</b>\n\n"
            f"📄 <b>Contract:</b> <code>{address}</code>\n"
            f"📦 <b>Name:</b> {safe_name}\n"
            f"🔐 <b>Result:</b> {safe_result}\n"
            f"🐛 <b>Findings:</b> {findings_count}\n\n"
            f"📝 <b>Summary:</b> {safe_summary}...\n"
        )

        bot.edit_message_text(message_text, message.chat.id, status.message_id, parse_mode="HTML")

        # 5. Send PDF
        with open(pdf_file, "rb") as document:
            bot.send_document(
                message.chat.id, 
                document, 
                caption="📑 Web3 Security Audit Report"
            )

    except Exception as e:
        error_msg = str(e)
        if "rate limit" in error_msg.lower():
            error_msg = "API Rate Limit hit. Please try again in a few seconds."
        elif "verified" in error_msg.lower():
            error_msg = "Contract is not verified on Etherscan."
            
        bot.edit_message_text(f"❌ Scan failed: {html.escape(error_msg)}", message.chat.id, status.message_id, parse_mode="HTML")
        print(f"Error during scan: {traceback.format_exc()}")
        
    finally:
        # Clean up PDF file to save storage
        if pdf_file and os.path.exists(pdf_file):
            os.remove(pdf_file)


# ============================================================
# RUN BOT
# ============================================================
if __name__ == "__main__":
    print("================================")
    print("🚀 Web3 Security Bot Started Successfully (Gemini 1.5 Flash)!")
    print("================================")
    try:
        bot.infinity_polling(skip_pending=True)
    except Exception as e:
        print(f"Bot stopped: {e}")

