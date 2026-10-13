"""Durable mailbox receipts and PDF filtering with realistic MIME messages."""
import io
import ssl
from email.message import EmailMessage
from PIL import Image
import pytest
from fastapi import HTTPException
from sqlalchemy import select, func
from app.db import SessionLocal, Integration, MailImport, Document
from app.security import encrypt, decrypt
from app import integrations
from app.storage import ROOT

CONFIG = {'host': 'imap.example.com', 'port': 993, 'username': 'user', 'password': 'private-mail-password',
          'folder': 'INBOX', 'attachment_filter': 'pdf', 'import_body': False}


def pdf():
    out = io.BytesIO();Image.new('RGB', (30, 30), 'white').save(out, format='PDF')
    return out.getvalue()


def message(attachments=(), body='Mail body'):
    mail = EmailMessage();mail['Subject'] = 'Invoice mail';mail.set_content(body)
    for filename, content, mime in attachments:
        main, sub = mime.split('/')
        mail.add_attachment(content, maintype=main, subtype=sub, filename=filename)
    return mail.as_bytes()


@pytest.fixture
def mailbox(monkeypatch):
    state = {'messages': {}, 'validity': [b'12345'], 'fetches': [], 'size_fetches': [], 'fail_fetch': set()}
    class Client:
        def __init__(self, host, port, ssl_context, timeout):
            assert ssl_context.verify_mode == ssl.CERT_REQUIRED
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def login(self, username, password):
            assert username == 'user' and password == CONFIG['password']
        def select(self, folder, readonly):
            assert readonly is True
            return 'OK', []
        def response(self, key):
            assert key == 'UIDVALIDITY'
            return key, state['validity']
        def uid(self, command, *args):
            if command == 'search':
                assert args == (None, 'ALL')
                return 'OK', [b' '.join(state['messages'])]
            assert command == 'fetch'
            uid, fields = args
            raw = state['messages'][uid]
            if fields == '(RFC822.SIZE)':
                state['size_fetches'].append(uid)
                return 'OK', [b'1 (RFC822.SIZE ' + str(len(raw)).encode() + b')']
            assert fields == '(BODY.PEEK[])'
            state['fetches'].append(uid)
            return ('NO', []) if uid in state['fail_fetch'] else ('OK', [(b'RFC822', raw)])
    monkeypatch.setattr(integrations.imaplib, 'IMAP4_SSL', Client)
    return state


@pytest.fixture
def integration(alice):
    tid = alice.post('/api/tenants', json={'name': 'Mail space'}).json()['id']
    with SessionLocal() as db:
        row = Integration(tenant_id=tid, kind='imap', enabled=True, config_encrypted=encrypt(CONFIG))
        db.add(row);db.commit();return row.id, tid


def run(ident):
    # New sessions simulate worker restarts: memory cannot provide deduplication.
    with SessionLocal() as db:
        return integrations.run_integration_once(db, db.get(Integration, ident))


def configure(ident, **changes):
    with SessionLocal() as db:
        row = db.get(Integration, ident)
        row.config_encrypted = encrypt(decrypt(row.config_encrypted) | changes);db.commit()


def documents(tid):
    with SessionLocal() as db:
        return [(d.filename, d.mime) for d in db.scalars(select(Document).where(Document.tenant_id == tid))]


def receipts(ident):
    with SessionLocal() as db:
        return db.scalar(select(func.count()).select_from(MailImport).where(MailImport.integration_id == ident))


def test_pdf_filter_checks_bytes_ignores_images_and_nonmatching_bodies(integration, mailbox):
    ident, tid = integration
    configure(ident, import_body=True)
    mailbox['messages'] = {
        b'1': message([('invoice.PDF', pdf(), 'application/octet-stream'), ('logo.txt', b'logo content', 'text/plain')]),
        b'2': message([('fake.pdf', b'Not a PDF', 'application/pdf')], body='Excluded mail body'),
        b'3': message(body='No attachments'),
    }
    assert run(ident) == '2 Dokumente importiert. 2 E-Mails ohne PDF-Anhang übersprungen.'
    assert sorted(mime for _, mime in documents(tid)) == ['application/pdf', 'text/plain']
    assert receipts(ident) == 3
    assert run(ident) == '0 Dokumente importiert.'
    assert mailbox['fetches'] == [b'1', b'2', b'3']


def test_pdf_attachment_without_filename_is_imported(integration, mailbox):
    ident, tid = integration
    mailbox['messages'][b'1'] = message([(None, pdf(), 'application/pdf')])
    assert run(ident) == '1 Dokumente importiert.'
    assert documents(tid)[0][0].endswith('.pdf')


def test_widen_filter_reconsiders_nonmatches_but_keeps_success_receipts(integration, mailbox):
    ident, tid = integration
    mailbox['messages'] = {b'1': message([('invoice.pdf', pdf(), 'application/pdf')]),
                           b'2': message([('invoice.txt', b'Text invoice', 'text/plain')])}
    assert '1 Dokumente importiert.' in run(ident)
    configure(ident, attachment_filter='all')
    assert run(ident) == '1 Dokumente importiert.'
    assert len(documents(tid)) == 2
    assert mailbox['fetches'] == [b'1', b'2', b'2']
    configure(ident, attachment_filter='pdf')
    assert run(ident) == '0 Dokumente importiert.'
    assert mailbox['fetches'] == [b'1', b'2', b'2']


def test_nonmatches_do_not_starve_later_pdf_mail(integration, mailbox):
    ident, tid = integration
    mailbox['messages'] = {str(i).encode(): message(body='No PDF') for i in range(1, 32)}
    mailbox['messages'][b'32'] = message([('invoice.pdf', pdf(), 'application/pdf')])
    assert '30 E-Mails ohne PDF-Anhang' in run(ident)
    assert not documents(tid)
    assert '1 Dokumente importiert.' in run(ident)
    assert len(documents(tid)) == 1
    assert len(mailbox['fetches']) == 32


def test_import_failure_rolls_back_receipts_and_files_and_can_retry(integration, mailbox, monkeypatch):
    ident, tid = integration
    content = pdf()
    mailbox['messages'][b'1'] = message([('first.pdf', content, 'application/pdf'), ('second.pdf', content, 'application/pdf')])
    original = integrations.save_document
    def fail_second(db, tenant, owner, filename, stream, source):
        if filename == 'second.pdf': raise HTTPException(413, 'Quota exceeded')
        return original(db, tenant, owner, filename, stream, source=source)
    monkeypatch.setattr(integrations, 'save_document', fail_second)
    assert 'fehlgeschlagen' in run(ident)
    assert receipts(ident) == 0 and not documents(tid)
    assert not list((ROOT/tid).glob('*/original'))
    monkeypatch.setattr(integrations, 'save_document', original)
    assert run(ident) == '1 Dokumente importiert.'  # Identical second attachment is deduplicated.
    assert receipts(ident) == 1 and len(documents(tid)) == 1


def test_transient_fetch_failure_is_not_marked_complete(integration, mailbox):
    ident, tid = integration
    mailbox['messages'][b'1'] = message([('invoice.pdf', pdf(), 'application/pdf')])
    mailbox['fail_fetch'] = {b'1'}
    assert run(ident) == '0 Dokumente importiert.'
    assert receipts(ident) == 0
    mailbox['fail_fetch'].clear()
    assert run(ident) == '1 Dokumente importiert.'


@pytest.mark.parametrize('change', ['validity', 'mailbox', 'user_port'])
def test_receipt_namespace_changes_and_checksums_prevent_duplicate_docs(integration, mailbox, change):
    ident, tid = integration
    mailbox['messages'][b'1'] = message([('invoice.pdf', pdf(), 'application/pdf')])
    assert run(ident) == '1 Dokumente importiert.'
    if change == 'validity': mailbox['validity'] = [b'54321']
    if change == 'mailbox': configure(ident, folder='Invoices')
    if change == 'user_port': configure(ident, port=1993)
    assert run(ident) == '0 Dokumente importiert.'
    assert receipts(ident) == 2 and len(documents(tid)) == 1
    assert mailbox['fetches'] == [b'1', b'1']


def test_missing_uidvalidity_does_not_create_unsafe_receipts(integration, mailbox):
    ident, tid = integration
    mailbox['messages'][b'1'] = message([('invoice.pdf', pdf(), 'application/pdf')])
    mailbox['validity'] = [None]
    assert 'fehlgeschlagen' in run(ident)
    assert not receipts(ident) and not documents(tid)


@pytest.mark.parametrize('bad_filter', ['unknown', None, True, []])
def test_filter_config_validation(alice, integration, bad_filter):
    _, tid = integration
    response = alice.put(f'/api/tenants/{tid}/integrations/imap', json={
        'enabled': True, 'config': CONFIG | {'attachment_filter': bad_filter}})
    assert response.status_code == 422


def test_filter_saved_and_secret_is_masked(alice, integration):
    _, tid = integration
    assert alice.put(f'/api/tenants/{tid}/integrations/imap', json={'enabled': True, 'config': CONFIG}).status_code == 200
    row = next(i for i in alice.get(f'/api/tenants/{tid}/integrations').json() if i['kind'] == 'imap')
    assert row['config']['attachment_filter'] == 'pdf'
    assert row['config']['password'] == '••••••••'
