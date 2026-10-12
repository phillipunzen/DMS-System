"""Local data minimisation. Masking is a heuristic, never anonymisation."""
import hashlib
import hmac
import json
import re
import time
import unicodedata
from .security import secret

MAX_AI_TEXT = 10000

# Country-specific lengths avoid swallowing the following supplier/date.
IBAN_LENGTHS = {'DE': 22, 'AT': 20, 'CH': 21, 'LI': 21, 'NL': 18, 'BE': 16,
    'FR': 27, 'GB': 22, 'ES': 24, 'IT': 27, 'PL': 28, 'LU': 20, 'DK': 18,
    'SE': 24, 'NO': 15, 'FI': 18, 'IE': 22, 'PT': 25, 'CZ': 24, 'SK': 24}
IBAN = re.compile(r'\b(?:' + '|'.join(
    country + r'[ \t]*\d[ \t]*\d(?:[ \t]*[A-Z0-9]){' + str(length - 4) + '}'
    for country, length in IBAN_LENGTHS.items()) + r'|[A-Z]{2}\d{2}[A-Z0-9]{11,30})\b', re.I)
EMAIL = re.compile(r'[\w.!#$%&\x27*+/=?^`{|}~-]+@[\w-]+(?:\.[\w-]+)+', re.U)
URL = re.compile(r'https?://[^\s<>]+', re.I)
PHONE = re.compile(r'(?<!\w)(?:\+\d{1,3}|00\d{1,3}|0\d{2,5})[ \t()./-]*\d(?:[ \t()./-]*\d){5,13}(?!\w)')
IDENTIFIER = re.compile(r'(?im)^(\s*(?:IBAN|BIC|Kontonummer|Bankverbindung|Steuernummer|Steuer-ID|USt[. -]*ID(?:Nr[.]?)?|Umsatzsteuer[ -]*ID|Kunden(?:nummer|[ -]*Nr[.]?)|Versicherungsnummer|Telefon|Tel[.]?|Mobil|Fax)\s*[:=]\s*)[^\n]+')


def minimise_text(text, limit=MAX_AI_TEXT):
    text = unicodedata.normalize('NFKC', text or '')
    text = re.sub(r'[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]', '', text)
    counts = {}
    for name, pattern, replacement in [
        ('Kennungen', IDENTIFIER, r'\1[KENNUNG]'),
        ('E-Mail-Adressen', EMAIL, '[EMAIL]'),
        ('Webadressen', URL, '[WEBADRESSE]'),
        ('Bankverbindungen', IBAN, '[IBAN]'),
        ('Telefonnummern', PHONE, '[TELEFON]'),
    ]:
        if name == 'Telefonnummern':
            def mask_phone(match):
                value = match.group(0)
                # Dates such as 01.12.2026 carry invoice information, not phone numbers.
                if re.fullmatch(r'\d{1,2}[./-]\d{1,2}[./-]\d{4}', value):
                    return value
                return replacement
            count = sum(1 for match in pattern.finditer(text) if mask_phone(match) != match.group(0))
            text = pattern.sub(mask_phone, text)
        else:
            text, count = pattern.subn(replacement, text)
        if count:
            counts[name] = count
    # Mask before clipping: an identifier crossing the limit must not leak partially.
    return {'text': text[:limit], 'redactions': counts, 'truncated': len(text) > limit}


def preview_signature(doc, integration, text, expires):
    payload = json.dumps([doc.tenant_id, doc.id, doc.text, doc.deleted_at is not None,
        doc.processed_at.isoformat() if doc.processed_at else None,
        integration.config_encrypted, integration.enabled, text, expires], ensure_ascii=False)
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def preview_token(doc, integration, text):
    expires = int(time.time()) + 600
    return str(expires) + '.' + preview_signature(doc, integration, text, expires)


def verify_preview(doc, integration, text, token):
    try:
        expiry, signature = token.split('.', 1)
        expires = int(expiry)
        return time.time() <= expires <= time.time() + 600 and hmac.compare_digest(
            signature, preview_signature(doc, integration, text, expires))
    except (ValueError, TypeError):
        return False
