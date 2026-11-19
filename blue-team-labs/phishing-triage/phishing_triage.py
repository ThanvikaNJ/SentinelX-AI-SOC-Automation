#!/usr/bin/env python3
"""Extract common phishing indicators from an EML/text file for analyst review."""
from __future__ import annotations
import argparse
from email import policy
from email.parser import BytesParser
from pathlib import Path
import re
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
RISKY_EXTENSIONS = {".exe", ".scr", ".js", ".vbs", ".iso", ".hta", ".bat", ".cmd"}

def inspect(path: Path) -> list[str]:
    msg = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    sender = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    subject = msg.get("Subject", "")
    body_parts = []
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            attachments.append(filename)
        elif part.get_content_type() == "text/plain":
            try:
                body_parts.append(part.get_content())
            except (LookupError, UnicodeDecodeError):
                pass
    body = "\n".join(body_parts)
    urls = sorted(set(URL_RE.findall(body)))
    findings = [f"Subject: {subject}", f"From: {sender}", f"Reply-To: {reply_to or '(not supplied)'}"]
    if reply_to and sender.split("@")[-1].strip("> ").lower() != reply_to.split("@")[-1].strip("> ").lower():
        findings.append("[REVIEW] From and Reply-To domains differ.")
    for url in urls:
        host = urlparse(url).hostname or "(unparsed)"
        findings.append(f"URL: {url} | host={host}")
        if host.startswith("xn--"):
            findings.append(f"[REVIEW] Punycode hostname: {host}")
    for name in attachments:
        findings.append(f"Attachment: {name}")
        if Path(name).suffix.lower() in RISKY_EXTENSIONS:
            findings.append(f"[HIGH REVIEW] Potentially risky attachment extension: {name}")
    if not urls and not attachments:
        findings.append("No URLs or named attachments extracted.")
    findings.append("Analyst note: validate context and headers; indicators alone do not prove phishing.")
    return findings

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("email_file", type=Path)
    args = parser.parse_args()
    try:
        print("\n".join(inspect(args.email_file)))
    except OSError as exc:
        parser.error(str(exc))

if __name__ == "__main__":
    main()
