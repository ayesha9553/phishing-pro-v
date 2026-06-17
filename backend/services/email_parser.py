"""Email file parser for .eml and .msg formats."""

import email
import re
import hashlib
from email import policy
from email.utils import parseaddr
from io import BytesIO
from bs4 import BeautifulSoup

from backend.models.schemas import EmailData


def parse_eml(content: bytes) -> EmailData:
    """Parse a .eml file from raw bytes into EmailData."""
    msg = email.message_from_bytes(content, policy=policy.default)
    return _extract_email_data(msg, content)


def parse_msg(content: bytes) -> EmailData:
    """Parse a .msg file from raw bytes into EmailData."""
    try:
        import extract_msg

        msg_file = extract_msg.Message(BytesIO(content))

        # Build EmailData from extract_msg's parsed data
        headers_dict = {}
        raw_header_lines = []
        if hasattr(msg_file, "header") and msg_file.header:
            header_msg = email.message_from_string(msg_file.header.as_string() if hasattr(msg_file.header, 'as_string') else str(msg_file.header), policy=policy.default)
            for key, value in header_msg.items():
                headers_dict[key.lower()] = str(value)
                raw_header_lines.append(f"{key}: {value}")

        # Extract basic fields
        sender_full = msg_file.sender or ""
        display_name, sender_email = parseaddr(sender_full)

        body_plain = msg_file.body or ""
        body_html = ""
        if hasattr(msg_file, "htmlBody") and msg_file.htmlBody:
            body_html = msg_file.htmlBody if isinstance(msg_file.htmlBody, str) else msg_file.htmlBody.decode("utf-8", errors="replace")

        # Extract attachment names and hashes
        attachment_names = []
        attachment_hashes = {}
        if hasattr(msg_file, "attachments"):
            for att in msg_file.attachments:
                name = getattr(att, "longFilename", None) or getattr(att, "shortFilename", None) or "unnamed"
                attachment_names.append(name)
                # Compute SHA256 of attachment
                payload = getattr(att, "data", b"")
                if payload:
                    sha256_hash = hashlib.sha256(payload).hexdigest()
                    attachment_hashes[name] = sha256_hash

        # Extract URLs
        urls = _extract_all_urls(body_plain, body_html)

        msg_file.close()

        return EmailData(
            subject=msg_file.subject or "",
            sender=sender_email or sender_full,
            sender_display_name=display_name,
            reply_to=headers_dict.get("reply-to", ""),
            recipient=msg_file.to or "",
            date=msg_file.date or "",
            message_id=headers_dict.get("message-id", ""),
            headers=headers_dict,
            raw_headers="\n".join(raw_header_lines),
            body_plain=body_plain,
            body_html=body_html,
            urls=urls,
            attachment_names=attachment_names,
            attachment_hashes=attachment_hashes,
            received_chain=_get_all_values(headers_dict, "received"),
            authentication_results=headers_dict.get("authentication-results", ""),
            dkim_signature=headers_dict.get("dkim-signature", ""),
            spf_record=headers_dict.get("received-spf", ""),
        )
    except Exception as e:
        raise ValueError(f"Failed to parse .msg file: {e}")


def parse_raw_email(raw_text: str) -> EmailData:
    """Parse raw email text (headers + body) into EmailData."""
    content = raw_text.encode("utf-8", errors="replace")
    msg = email.message_from_bytes(content, policy=policy.default)
    return _extract_email_data(msg, content)


def _extract_email_data(msg: email.message.Message, raw_bytes: bytes) -> EmailData:
    """Extract EmailData from a parsed email.message.Message object."""
    # Headers
    headers_dict = {}
    raw_header_lines = []
    received_chain = []

    for key, value in msg.items():
        key_lower = key.lower()
        headers_dict[key_lower] = str(value)
        raw_header_lines.append(f"{key}: {value}")
        if key_lower == "received":
            received_chain.append(str(value))

    # Sender
    sender_full = str(msg.get("from", ""))
    display_name, sender_email = parseaddr(sender_full)

    # Reply-To
    reply_to = str(msg.get("reply-to", ""))

    # Recipient
    recipient = str(msg.get("to", ""))

    # Date
    date = str(msg.get("date", ""))

    # Message-ID
    message_id = str(msg.get("message-id", ""))

    # Body extraction
    body_plain = ""
    body_html = ""
    attachment_names = []
    attachment_hashes = {}

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in disposition or part.get_filename():
                filename = part.get_filename() or "unnamed"
                attachment_names.append(filename)
                
                payload_bytes = part.get_payload(decode=True)
                if payload_bytes:
                    sha256_hash = hashlib.sha256(payload_bytes).hexdigest()
                    attachment_hashes[filename] = sha256_hash
                continue

            if content_type == "text/plain" and not body_plain:
                payload = part.get_content()
                body_plain = payload if isinstance(payload, str) else str(payload)
            elif content_type == "text/html" and not body_html:
                payload = part.get_content()
                body_html = payload if isinstance(payload, str) else str(payload)
    else:
        content_type = msg.get_content_type()
        payload = msg.get_content()
        text = payload if isinstance(payload, str) else str(payload)
        if content_type == "text/html":
            body_html = text
        else:
            body_plain = text

    # Extract URLs
    urls = _extract_all_urls(body_plain, body_html)

    return EmailData(
        subject=str(msg.get("subject", "")),
        sender=sender_email or sender_full,
        sender_display_name=display_name,
        reply_to=reply_to,
        recipient=recipient,
        date=date,
        message_id=message_id,
        headers=headers_dict,
        raw_headers="\n".join(raw_header_lines),
        body_plain=body_plain,
        body_html=body_html,
        urls=urls,
        attachment_names=attachment_names,
        attachment_hashes=attachment_hashes,
        received_chain=received_chain,
        authentication_results=headers_dict.get("authentication-results", ""),
        dkim_signature=headers_dict.get("dkim-signature", ""),
        spf_record=headers_dict.get("received-spf", ""),
    )


def _extract_all_urls(plain_text: str, html_text: str) -> list[str]:
    """Extract all unique URLs from both plain text and HTML."""
    urls = set()

    # From plain text
    if plain_text:
        pattern = r'https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:/[^\s<>"{}|\\^`\[\]]*)?'
        urls.update(re.findall(pattern, plain_text))

    # From HTML
    if html_text:
        try:
            soup = BeautifulSoup(html_text, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                if href.startswith(("http://", "https://")):
                    urls.add(href)
            # Also extract from img src, form action, etc.
            for tag in soup.find_all(["img", "script", "iframe"], src=True):
                src = tag["src"].strip()
                if src.startswith(("http://", "https://")):
                    urls.add(src)
            for form_tag in soup.find_all("form", action=True):
                action = form_tag["action"].strip()
                if action.startswith(("http://", "https://")):
                    urls.add(action)
        except Exception:
            pass

    return list(urls)


def _get_all_values(headers: dict, key: str) -> list[str]:
    """Get all values for a header key (handles duplicates)."""
    # The dict only stores the last value, but received_chain is built separately
    value = headers.get(key, "")
    return [value] if value else []
