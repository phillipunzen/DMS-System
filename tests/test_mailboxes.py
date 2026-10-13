"""Mailbox administration, receipt isolation and continued worker polling."""
import pytest
from sqlalchemy import select
from app.db import SessionLocal, Integration, MailImport
from app.security import decrypt
from app import integrations, worker
from test_mail_import import CONFIG, mailbox, message, pdf, run, receipts, documents


def add(client, tid, name='Invoices', **config):
    return client.post(f'/api/tenants/{tid}/mailboxes', json={
        'name': name, 'enabled': True, 'config': CONFIG | config})


def test_multiple_mailboxes_have_independent_settings_and_encrypted_secrets(alice):
    tid = alice.post('/api/tenants', json={'name': 'Mail'}).json()['id']
    first = add(alice, tid).json()
    second = add(alice, tid, 'Contracts', username='contracts', password='other-private-password', attachment_filter='all').json()
    assert first['id'] != second['id']
    rows = alice.get(f'/api/tenants/{tid}/mailboxes').json()
    assert {row['name'] for row in rows} == {'Invoices', 'Contracts'}
    assert {row['config']['attachment_filter'] for row in rows} == {'pdf', 'all'}
    assert all(row['config']['password'] == '••••••••' for row in rows)
    with SessionLocal() as db:
        saved = db.get(Integration, second['id'])
        assert 'other-private-password' not in saved.config_encrypted
        assert decrypt(saved.config_encrypted)['password'] == 'other-private-password'
    configs = alice.get(f'/api/tenants/{tid}/integrations').json()
    assert len([row for row in configs if row['kind'] == 'imap']) == 2
    updated = alice.put(f"/api/tenants/{tid}/mailboxes/{first['id']}", json={
        'name': 'Renamed', 'enabled': False, 'config': first['config']})
    assert updated.status_code == 200 and not updated.json()['enabled']
    with SessionLocal() as db:
        assert decrypt(db.get(Integration, first['id']).config_encrypted)['password'] == CONFIG['password']
        assert db.get(Integration, second['id']).enabled


def test_pause_retains_receipts_and_remove_retains_documents(alice, mailbox):
    tid = alice.post('/api/tenants', json={'name': 'Mail'}).json()['id']
    row = add(alice, tid).json();ident = row['id']
    mailbox['messages'][b'1'] = message([('invoice.pdf', pdf(), 'application/pdf')])
    assert alice.post(f'/api/tenants/{tid}/mailboxes/{ident}/run').json()['status'] == '1 Dokumente importiert.'
    payload = {'name': row['name'], 'enabled': False, 'config': row['config']}
    assert alice.put(f'/api/tenants/{tid}/mailboxes/{ident}', json=payload).status_code == 200
    assert alice.post(f'/api/tenants/{tid}/mailboxes/{ident}/run').status_code == 400
    assert receipts(ident) == 1
    payload['enabled'] = True
    alice.put(f'/api/tenants/{tid}/mailboxes/{ident}', json=payload)
    assert alice.post(f'/api/tenants/{tid}/mailboxes/{ident}/run').json()['status'] == '0 Dokumente importiert.'
    assert mailbox['fetches'] == [b'1']
    assert alice.delete(f'/api/tenants/{tid}/mailboxes/{ident}').status_code == 200
    assert receipts(ident) == 0 and len(documents(tid)) == 1
    assert alice.get(f'/api/tenants/{tid}/mailboxes').json() == []


def test_identical_uids_are_tracked_per_connection_with_independent_filters(alice, mailbox):
    tid = alice.post('/api/tenants', json={'name': 'Mail'}).json()['id']
    first = add(alice, tid).json()['id']
    second = add(alice, tid, 'All attachments', attachment_filter='all').json()['id']
    mailbox['messages'][b'1'] = message([('invoice.pdf', pdf(), 'application/pdf'), ('contract.txt', b'Text contract', 'text/plain')])
    assert run(first) == '1 Dokumente importiert.'
    assert run(second) == '1 Dokumente importiert.'  # Shared PDF deduplicated; text imported.
    assert receipts(first) == receipts(second) == 1 and len(documents(tid)) == 2
    assert run(first) == run(second) == '0 Dokumente importiert.'
    assert mailbox['fetches'] == [b'1', b'1']


def test_worker_failure_in_one_mailbox_does_not_stop_other_mailboxes(alice, mailbox, monkeypatch):
    tid = alice.post('/api/tenants', json={'name': 'Mail'}).json()['id']
    bad = add(alice, tid, 'Unavailable', host='offline.example.com').json()['id']
    good = add(alice, tid, 'Available').json()['id']
    original = integrations.imaplib.IMAP4_SSL
    def connect(host, *args, **kwargs):
        if host == 'offline.example.com': raise OSError('Connection failed')
        return original(host, *args, **kwargs)
    monkeypatch.setattr(integrations.imaplib, 'IMAP4_SSL', connect)
    mailbox['messages'][b'1'] = message([('invoice.pdf', pdf(), 'application/pdf')])
    worker._tick()
    with SessionLocal() as db:
        assert 'fehlgeschlagen' in db.get(Integration, bad).last_status
        assert db.get(Integration, good).last_status == '1 Dokumente importiert.'
        assert db.get(Integration, good).last_run is not None
    assert receipts(bad) == 0 and receipts(good) == 1


def test_mailbox_endpoints_are_owner_only_and_tenant_scoped(alice, bob):
    tid = alice.post('/api/tenants', json={'name': 'Private'}).json()['id']
    other = alice.post('/api/tenants', json={'name': 'Other private'}).json()['id']
    ident = add(alice, tid).json()['id']
    payload = {'name': 'Forgery', 'enabled': True, 'config': CONFIG}
    paths = [(f'/api/tenants/{tid}/mailboxes', 'get', None),
             (f'/api/tenants/{tid}/mailboxes', 'post', payload),
             (f'/api/tenants/{tid}/mailboxes/{ident}', 'put', payload),
             (f'/api/tenants/{tid}/mailboxes/{ident}', 'delete', None),
             (f'/api/tenants/{tid}/mailboxes/{ident}/run', 'post', None)]
    for path, method, data in paths:
        response = getattr(bob, method)(path, **({'json': data} if data else {}))
        assert response.status_code in {403, 404}
    for method, suffix in [('put', ''), ('delete', ''), ('post', '/run')]:
        response = getattr(alice, method)(f'/api/tenants/{other}/mailboxes/{ident}{suffix}', **({'json':payload} if method == 'put' else {}))
        assert response.status_code == 404
    # Even a manager in the correct tenant cannot read mailbox credentials.
    invitation = alice.post(f'/api/tenants/{tid}/invitations', json={'email': 'bob@example.com', 'role': 'manager'}).json()
    assert bob.post('/api/invitations/accept', json={'token': invitation['path'].split('=')[-1]}).status_code == 200
    assert bob.get(f'/api/tenants/{tid}/mailboxes').status_code == 403


def test_legacy_api_updates_only_default_connection(alice):
    tid = alice.post('/api/tenants', json={'name': 'Mail'}).json()['id']
    additional = add(alice, tid, 'Additional').json()['id']
    path = f'/api/tenants/{tid}/integrations/imap'
    assert alice.put(path, json={'enabled': True, 'config': CONFIG | {'username': 'default'}}).status_code == 200
    with SessionLocal() as db:
        default = db.scalar(select(Integration).where(Integration.tenant_id == tid, Integration.account_key == ''))
        assert default.id != additional
        ident = default.id
        db.add(MailImport(integration_id=ident, message_key='existing-receipt'));db.commit()
    assert alice.put(path, json={'enabled': False, 'config': CONFIG}).status_code == 200
    with SessionLocal() as db:
        assert db.get(Integration, additional).enabled
        assert not db.get(Integration, ident).enabled
    assert receipts(ident) == 1


@pytest.mark.parametrize('name', ['', '   ', 'x' * 151])
def test_mailbox_names_are_validated(alice, name):
    tid = alice.post('/api/tenants', json={'name': 'Mail'}).json()['id']
    assert add(alice, tid, name).status_code == 422


def test_masked_password_cannot_create_an_active_mailbox(alice):
    tid = alice.post('/api/tenants', json={'name': 'Mail'}).json()['id']
    assert add(alice, tid, password='••••••••').status_code == 422
