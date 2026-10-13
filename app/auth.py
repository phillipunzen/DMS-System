import ssl
from datetime import timedelta
from urllib.parse import urlparse
from fastapi import HTTPException
from sqlalchemy import select, case
from ldap3 import Server, Connection, Tls, AUTO_BIND_NO_TLS, AUTO_BIND_TLS_BEFORE_BIND
from ldap3.utils.conv import escape_filter_chars
from .db import User, Identity, AuthAttempt, now, engine
from .security import setting, decrypt, digest, current_user


def rate_limit(db, email, ip):
    from sqlalchemy.dialects.mysql import insert as mysql_insert
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert
    timestamp = now()
    keys = sorted([digest('email:' + email), digest('ip:' + ip)])
    for key in keys:
        insert = mysql_insert if engine.dialect.name == 'mysql' else sqlite_insert
        statement = insert(AuthAttempt).values(key=key, count=1, reset_at=timestamp + timedelta(minutes=15))
        values = {'count': case((AuthAttempt.reset_at < timestamp, 1), else_=AuthAttempt.count + 1),
                  'reset_at': case((AuthAttempt.reset_at < timestamp, timestamp + timedelta(minutes=15)), else_=AuthAttempt.reset_at)}
        statement = statement.on_duplicate_key_update(**values) if engine.dialect.name == 'mysql' else statement.on_conflict_do_update(index_elements=['key'], set_=values)
        db.execute(statement)
    counts = db.scalars(select(AuthAttempt.count).where(AuthAttempt.key.in_(keys))).all()
    db.commit()
    if any(count > 20 for count in counts):
        raise HTTPException(429, 'Zu viele Anmeldeversuche. Bitte in 15 Minuten erneut versuchen.')


def external_user(db, provider, subject, email, name, request=None):
    identity = db.scalar(select(Identity).where(Identity.provider == provider, Identity.subject == subject))
    if identity:
        user = db.get(User, identity.user_id)
        if not user.active:
            raise HTTPException(401, 'Konto ist gesperrt.')
        return user
    email = email.lower()
    user = db.scalar(select(User).where(User.email == email))
    if user:
        # Linking an existing local account requires a current authenticated session.
        try:
            authenticated = current_user(request, db) if request else None
        except HTTPException:
            authenticated = None
        if not authenticated or authenticated.id != user.id:
            raise HTTPException(409, 'Bestehendes Konto zuerst lokal anmelden, dann OIDC verknüpfen.')
    else:
        # Only called after the configured LDAP/OIDC provider authenticated the user.
        # Provider access controls account creation; tenant access still requires membership.
        user = User(email=email, name=name[:150])
        db.add(user)
        db.flush()
    db.add(Identity(user_id=user.id, provider=provider, subject=subject))
    db.commit()
    return user


def validate_auth(kind, config, enabled):
    if not enabled:
        return
    required = {'oidc': ['discovery_url', 'client_id', 'client_secret', 'redirect_uri'], 'ldap': ['host', 'base_dn', 'bind_dn', 'bind_password']}[kind]
    if any(not config.get(k) for k in required):
        raise HTTPException(422, 'Pflichtfelder der Authentifizierung fehlen.')
    if kind == 'oidc':
        if not isinstance(config.get('require_verified_email', False), bool):
            raise HTTPException(422, 'E-Mail-Bestätigung muss ein Wahrheitswert sein.')
        if urlparse(config['discovery_url']).scheme != 'https' or urlparse(config['redirect_uri']).scheme not in {'http', 'https'}:
            raise HTTPException(422, 'OIDC-Discovery muss HTTPS verwenden.')
    else:
        config['port'] = int(config.get('port', 636))
        if not 1 <= config['port'] <= 65535:
            raise HTTPException(422, 'Ungültiger LDAP-Port.')
        if config.get('transport', 'ldaps') not in {'ldaps', 'starttls'}:
            raise HTTPException(422, 'LDAP benötigt LDAPS oder StartTLS.')
        if '{email}' not in config.get('filter', '(mail={email})'):
            raise HTTPException(422, 'Suchfilter muss {email} enthalten.')


def ldap_authenticate(db, email, password):
    value = setting(db, 'ldap')
    if not value or not password:
        raise HTTPException(401, 'LDAP-Anmeldung nicht verfügbar.')
    config = decrypt(value)
    use_ssl = config.get('transport', 'ldaps') == 'ldaps'
    tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=config.get('ca_file') or None)
    server = Server(config['host'], port=int(config.get('port', 636)), use_ssl=use_ssl, tls=tls, connect_timeout=10)
    auto_bind = AUTO_BIND_NO_TLS if use_ssl else AUTO_BIND_TLS_BEFORE_BIND
    try:
        with Connection(server, user=config['bind_dn'], password=config['bind_password'], auto_bind=auto_bind, auto_referrals=False, receive_timeout=10) as lookup:
            lookup.search(config['base_dn'], config.get('filter', '(mail={email})').replace('{email}', escape_filter_chars(email)), attributes=['mail', 'displayName'], size_limit=2)
            if len(lookup.entries) != 1:
                raise ValueError('Benutzer nicht eindeutig')
            entry = lookup.entries[0]
            dn = entry.entry_dn
            real_email = str(entry.mail.value).lower()
            name = str(entry.displayName.value or email)
        with Connection(server, user=dn, password=password, auto_bind=auto_bind, auto_referrals=False, receive_timeout=10):
            if real_email != email:
                raise ValueError('E-Mail stimmt nicht überein')
        return external_user(db, 'ldap:' + config['host'], dn, email, name)
    except Exception:
        raise HTTPException(401, 'LDAP-Anmeldung fehlgeschlagen. Bestehende lokale Konten müssen getrennt verwaltet werden.')
