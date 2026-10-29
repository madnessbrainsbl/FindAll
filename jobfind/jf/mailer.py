"""Single, user-approved SMTP delivery. Credentials stay in memory only."""

from __future__ import annotations

import re
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr


EMAIL_RE = re.compile(r"^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$")


def send_one(recipient: str, subject: str, body: str, sender: str, sender_name: str,
             smtp_user: str, password: str, host: str, port: int, security: str) -> None:
    recipient, sender, smtp_user = recipient.strip(), sender.strip(), smtp_user.strip()
    if not EMAIL_RE.fullmatch(recipient) or not EMAIL_RE.fullmatch(sender):
        raise ValueError("Check the recipient and sender email addresses")
    if sender.casefold() != smtp_user.casefold():
        raise ValueError("Sender email must match the SMTP username")
    if any(ch in sender_name for ch in "\r\n"):
        raise ValueError("Sender name must not contain line breaks")
    if not subject.strip() or not body.strip() or "\r" in subject or "\n" in subject:
        raise ValueError("Subject and message are required; subject must not contain line breaks")
    if not host.strip() or not (1 <= int(port) <= 65535):
        raise ValueError("Check the SMTP server and port")
    if security not in ("STARTTLS", "SSL"):
        raise ValueError("STARTTLS and SSL are supported")

    message = EmailMessage()
    message["From"] = formataddr((sender_name.strip(), sender)) if sender_name.strip() else sender
    message["To"] = recipient
    message["Subject"] = subject.strip()
    message.set_content(body.rstrip() + "\n")
    context = ssl.create_default_context()
    if security == "SSL":
        with smtplib.SMTP_SSL(host.strip(), int(port), timeout=25, context=context) as smtp:
            smtp.login(smtp_user, password)
            refused = smtp.send_message(message)
    else:
        with smtplib.SMTP(host.strip(), int(port), timeout=25) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
            smtp.login(smtp_user, password)
            refused = smtp.send_message(message)
    if refused:
        raise RuntimeError(f"The server rejected the recipient: {refused}")
