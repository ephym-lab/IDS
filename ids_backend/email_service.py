"""
email_service.py
----------------
Async email notification service for the IDS backend.

Uses Python's built-in smtplib (run in a thread-pool executor so it stays
non-blocking inside FastAPI's event loop).

Configuration (loaded from .env)
---------------------------------
SMTP_HOST     — e.g. smtp.gmail.com
SMTP_PORT     — e.g. 587  (STARTTLS)
SMTP_USER     — your Gmail / SMTP username
SMTP_PASSWORD — your Gmail App Password (not your account password!)
FROM_EMAIL    — sender address shown in the email
FROM_NAME     — friendly sender name shown in the email

Gmail note
----------
You must generate an App Password at:
  https://myaccount.google.com/apppasswords
(Requires 2-Step Verification to be ON for your Google account.)
"""

import asyncio
import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SMTP config
# ---------------------------------------------------------------------------

SMTP_HOST: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER: str = os.getenv("SMTP_USER", "")
SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
FROM_EMAIL: str = os.getenv("FROM_EMAIL", SMTP_USER)
FROM_NAME: str = os.getenv("FROM_NAME", "IDS Alert System")


# ---------------------------------------------------------------------------
# HTML email template
# ---------------------------------------------------------------------------

def _build_html(
    attack_type: str,
    severity: str,
    src_ip: str,
    dst_ip: str,
    confidence: float,
    timestamp: str,
) -> str:
    """Build a richly-formatted HTML alert email body."""
    confidence_pct = f"{confidence * 100:.1f}%"
    severity_color = {
        "High": "#ef4444",
        "Medium": "#f97316",
        "Low": "#eab308",
    }.get(severity, "#6b7280")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>IDS High Severity Alert</title>
</head>
<body style="margin:0;padding:0;background:#0f172a;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0f172a;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0"
               style="background:#1e293b;border-radius:12px;overflow:hidden;
                      box-shadow:0 4px 32px rgba(0,0,0,0.5);">

          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#1e3a5f,#0f172a);
                        padding:32px 40px;border-bottom:2px solid {severity_color};">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td>
                    <span style="font-size:22px;font-weight:700;color:#f8fafc;
                                 letter-spacing:1px;">🛡️ Network IDS</span>
                  </td>
                  <td align="right">
                    <span style="background:{severity_color};color:#fff;font-size:12px;
                                 font-weight:700;padding:4px 12px;border-radius:20px;
                                 letter-spacing:1px;text-transform:uppercase;">
                      {severity} SEVERITY
                    </span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Alert banner -->
          <tr>
            <td style="background:{severity_color}18;border-left:4px solid {severity_color};
                        padding:20px 40px;">
              <p style="margin:0;font-size:20px;font-weight:700;color:{severity_color};">
                ⚠&nbsp; High Severity Threat Detected
              </p>
              <p style="margin:6px 0 0;font-size:13px;color:#94a3b8;">
                Your IDS system has detected a potential network intrusion that requires immediate attention.
              </p>
            </td>
          </tr>

          <!-- Details table -->
          <tr>
            <td style="padding:32px 40px;">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td colspan="2" style="padding-bottom:16px;">
                    <span style="font-size:13px;font-weight:600;color:#64748b;
                                 text-transform:uppercase;letter-spacing:1px;">
                      Detection Details
                    </span>
                  </td>
                </tr>

                <!-- Attack Type -->
                <tr>
                  <td style="padding:12px 0;border-top:1px solid #334155;
                              font-size:13px;color:#64748b;width:40%;">Attack Type</td>
                  <td style="padding:12px 0;border-top:1px solid #334155;
                              font-size:14px;font-weight:600;color:#f8fafc;">{attack_type}</td>
                </tr>

                <!-- Severity -->
                <tr>
                  <td style="padding:12px 0;border-top:1px solid #334155;
                              font-size:13px;color:#64748b;">Severity</td>
                  <td style="padding:12px 0;border-top:1px solid #334155;">
                    <span style="background:{severity_color};color:#fff;font-size:12px;
                                 font-weight:700;padding:3px 10px;border-radius:12px;">
                      {severity}
                    </span>
                  </td>
                </tr>

                <!-- Source IP -->
                <tr>
                  <td style="padding:12px 0;border-top:1px solid #334155;
                              font-size:13px;color:#64748b;">Source IP</td>
                  <td style="padding:12px 0;border-top:1px solid #334155;
                              font-size:14px;font-weight:600;color:#f8fafc;
                              font-family:monospace;">{src_ip}</td>
                </tr>

                <!-- Destination IP -->
                <tr>
                  <td style="padding:12px 0;border-top:1px solid #334155;
                              font-size:13px;color:#64748b;">Destination IP</td>
                  <td style="padding:12px 0;border-top:1px solid #334155;
                              font-size:14px;font-weight:600;color:#f8fafc;
                              font-family:monospace;">{dst_ip}</td>
                </tr>

                <!-- Confidence -->
                <tr>
                  <td style="padding:12px 0;border-top:1px solid #334155;
                              font-size:13px;color:#64748b;">ML Confidence</td>
                  <td style="padding:12px 0;border-top:1px solid #334155;">
                    <span style="font-size:18px;font-weight:700;color:{severity_color};">
                      {confidence_pct}
                    </span>
                  </td>
                </tr>

                <!-- Timestamp -->
                <tr>
                  <td style="padding:12px 0;border-top:1px solid #334155;
                              font-size:13px;color:#64748b;">Detected At</td>
                  <td style="padding:12px 0;border-top:1px solid #334155;
                              font-size:13px;color:#94a3b8;font-family:monospace;">{timestamp}</td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- CTA note -->
          <tr>
            <td style="padding:0 40px 32px;">
              <p style="margin:0;font-size:13px;color:#64748b;line-height:1.6;">
                Please log in to your IDS dashboard to review this alert and take appropriate action.
                If this alert was expected (e.g. a penetration test), no action is needed.
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#0f172a;padding:20px 40px;border-top:1px solid #1e293b;">
              <p style="margin:0;font-size:12px;color:#475569;text-align:center;">
                This is an automated message from your Network Intrusion Detection System.<br/>
                Do not reply to this email.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Sending logic
# ---------------------------------------------------------------------------

def _send_smtp(recipients: list[str], subject: str, html_body: str) -> None:
    """
    Synchronous SMTP send — runs inside a thread-pool executor.
    Uses STARTTLS (port 587) which works for Gmail, Outlook, etc.
    """
    if not SMTP_USER or not SMTP_PASSWORD:
        logger.warning(
            "Email notification skipped — SMTP_USER / SMTP_PASSWORD not configured in .env"
        )
        return

    if not recipients:
        logger.info("Email notification skipped — no registered users found.")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{FROM_NAME} <{FROM_EMAIL}>"
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(FROM_EMAIL, recipients, msg.as_string())
        logger.info("Alert email sent to %d recipient(s).", len(recipients))
    except smtplib.SMTPAuthenticationError:
        logger.error(
            "SMTP authentication failed. Check SMTP_USER and SMTP_PASSWORD in your .env file.\n"
            "If using Gmail, make sure you are using an App Password, not your account password.\n"
            "Generate one at: https://myaccount.google.com/apppasswords"
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to send alert email: %s", exc)


async def notify_alert(
    *,
    attack_type: str,
    severity: str,
    src_ip: str,
    dst_ip: str,
    confidence: float,
    timestamp: str,
    recipients: list[str],   # pass [current_user_email] for single, all emails for broadcast
) -> None:
    """Send an alert email. Caller decides who receives it."""
    if not recipients:
        return

    subject = f"🚨 [{severity}] {attack_type} Attack Detected — Network IDS Alert"
    html_body = _build_html(
        attack_type=attack_type,
        severity=severity,
        src_ip=src_ip,
        dst_ip=dst_ip,
        confidence=confidence,
        timestamp=timestamp,
    )

    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _send_smtp, recipients, subject, html_body)


# ---------------------------------------------------------------------------
# OTP email
# ---------------------------------------------------------------------------

def _build_otp_html(otp: str, purpose: str, expire_minutes: int) -> str:
    """Build a styled HTML email body for OTP delivery."""
    action = "create your account" if purpose == "signup" else "log in to your account"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Your IDS Verification Code</title>
</head>
<body style="margin:0;padding:0;background:#0f172a;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0f172a;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="560" cellpadding="0" cellspacing="0"
               style="background:#1e293b;border-radius:12px;overflow:hidden;
                      box-shadow:0 4px 32px rgba(0,0,0,0.5);">

          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#1e3a5f,#0f172a);
                        padding:28px 40px;border-bottom:2px solid #3b82f6;">
              <span style="font-size:20px;font-weight:700;color:#f8fafc;
                           letter-spacing:1px;">🛡️ Network IDS</span>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:36px 40px;">
              <p style="margin:0 0 8px;font-size:22px;font-weight:700;color:#f8fafc;">
                Verification Code
              </p>
              <p style="margin:0 0 28px;font-size:14px;color:#94a3b8;line-height:1.6;">
                Use the code below to {action}. It expires in {expire_minutes} minutes.
              </p>

              <!-- OTP box -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td align="center">
                    <div style="display:inline-block;background:#0f172a;border:2px solid #3b82f6;
                                border-radius:12px;padding:20px 40px;margin:0 auto;">
                      <span style="font-size:42px;font-weight:800;letter-spacing:12px;
                                   color:#3b82f6;font-family:monospace;">{otp}</span>
                    </div>
                  </td>
                </tr>
              </table>

              <p style="margin:28px 0 0;font-size:13px;color:#64748b;line-height:1.6;">
                If you didn't request this, you can safely ignore this email. Do not share this
                code with anyone.
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#0f172a;padding:18px 40px;border-top:1px solid #1e293b;">
              <p style="margin:0;font-size:12px;color:#475569;text-align:center;">
                This is an automated message from your Network Intrusion Detection System.<br/>
                Do not reply to this email.
              </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


async def send_otp_email(
    *,
    email: str,
    otp: str,
    purpose: str = "login",   # "signup" | "login"
    expire_minutes: int = 10,
) -> None:
    """Send the OTP verification code to *email*."""
    subject = "🔐 Your IDS Verification Code"
    html_body = _build_otp_html(otp=otp, purpose=purpose, expire_minutes=expire_minutes)
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _send_smtp, [email], subject, html_body)
