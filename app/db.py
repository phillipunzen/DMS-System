import os
import uuid
from datetime import datetime, timezone
from sqlalchemy import create_engine, String, Text, Integer, Boolean, DateTime, Date, ForeignKey, UniqueConstraint, JSON, BigInteger
from sqlalchemy.orm import DeclarativeBase, mapped_column, sessionmaker
from sqlalchemy.dialects.mysql import LONGTEXT, DATETIME
Timestamp = DateTime().with_variant(DATETIME(fsp=6), "mysql")


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def uid():
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


engine = create_engine(os.getenv('DATABASE_URL', 'sqlite:///./dev.db'), pool_pre_ping=True,
                       **({'connect_args': {'check_same_thread': False}} if os.getenv('DATABASE_URL', 'sqlite:').startswith('sqlite:') else {}))
SessionLocal = sessionmaker(engine, expire_on_commit=False)


class User(Base):
    __tablename__ = 'users'
    id = mapped_column(String(36), primary_key=True, default=uid)
    email = mapped_column(String(254), unique=True, nullable=False)
    name = mapped_column(String(150), nullable=False)
    password_hash = mapped_column(Text, nullable=True)
    admin = mapped_column(Boolean, default=False)
    active = mapped_column(Boolean, default=True)
    created_at = mapped_column(Timestamp, default=now)


class Tenant(Base):
    __tablename__ = 'tenants'
    id = mapped_column(String(36), primary_key=True, default=uid)
    name = mapped_column(String(150), nullable=False)
    created_at = mapped_column(Timestamp, default=now)
    quota_mb = mapped_column(Integer, default=10240)
    workflow_enabled = mapped_column(Boolean, default=False, nullable=False)


class Membership(Base):
    __tablename__ = 'memberships'
    __table_args__ = (UniqueConstraint('tenant_id', 'user_id'),)
    id = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id = mapped_column(String(36), ForeignKey('tenants.id'), index=True)
    user_id = mapped_column(String(36), ForeignKey('users.id'), index=True)
    role = mapped_column(String(20), nullable=False)


class LoginSession(Base):
    __tablename__ = 'sessions'
    token_hash = mapped_column(String(64), primary_key=True)
    user_id = mapped_column(String(36), ForeignKey('users.id'), index=True)
    expires_at = mapped_column(Timestamp, nullable=False)


class Identity(Base):
    __tablename__ = 'identities'
    __table_args__ = (UniqueConstraint('provider', 'subject'),)
    id = mapped_column(String(36), primary_key=True, default=uid)
    user_id = mapped_column(String(36), ForeignKey('users.id'))
    provider = mapped_column(String(255), nullable=False)
    subject = mapped_column(String(255), nullable=False)


class Folder(Base):
    __tablename__ = 'folders'
    __table_args__ = (UniqueConstraint('tenant_id', 'name'),)
    id = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id = mapped_column(String(36), ForeignKey('tenants.id'), index=True)
    name = mapped_column(String(150), nullable=False)
    color = mapped_column(String(20), default='green')
    restricted = mapped_column(Boolean, default=False, nullable=False)


class Document(Base):
    __tablename__ = 'documents'
    id = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id = mapped_column(String(36), ForeignKey('tenants.id'), index=True)
    uploader_id = mapped_column(String(36), ForeignKey('users.id'))
    folder_id = mapped_column(String(36), ForeignKey('folders.id'), nullable=True)
    title = mapped_column(String(255), nullable=False)
    filename = mapped_column(String(255), nullable=False)
    mime = mapped_column(String(100), nullable=False)
    size = mapped_column(BigInteger, nullable=False)
    sha256 = mapped_column(String(64), index=True)
    status = mapped_column(String(20), default='queued', index=True)
    error = mapped_column(String(255), nullable=True)
    text = mapped_column(Text().with_variant(LONGTEXT, 'mysql'), default='')
    supplier = mapped_column(String(150), default='')
    doc_type = mapped_column(String(100), default='Sonstiges')
    tags = mapped_column(JSON, default=list)
    amount = mapped_column(String(30), nullable=True)
    due_date = mapped_column(Date, nullable=True, index=True)
    paid = mapped_column(Boolean, default=False)
    source = mapped_column(String(30), default='upload')
    created_at = mapped_column(Timestamp, default=now, index=True)
    deleted_at = mapped_column(Timestamp, nullable=True)
    processed_at = mapped_column(Timestamp, nullable=True)
    heartbeat_at = mapped_column(Timestamp, nullable=True)
    current_version = mapped_column(Integer, default=1, nullable=False)
    restricted = mapped_column(Boolean, default=False, nullable=False)
    review_status = mapped_column(String(20), default='none', nullable=False)
    ai_pending = mapped_column(Boolean, default=False, nullable=False)
    ai_retry_at = mapped_column(Timestamp, nullable=True)
    ai_attempts = mapped_column(Integer, default=0, nullable=False)


class Rule(Base):
    __tablename__ = 'rules'
    id = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id = mapped_column(String(36), ForeignKey('tenants.id'), index=True)
    name = mapped_column(String(150), nullable=False)
    field = mapped_column(String(20), nullable=False)
    contains = mapped_column(String(150), nullable=False)
    folder_id = mapped_column(String(36), ForeignKey('folders.id'), nullable=True)
    filename_template = mapped_column(String(255), nullable=True)
    priority = mapped_column(Integer, default=100)
    enabled = mapped_column(Boolean, default=True)


class Invitation(Base):
    __tablename__ = 'invitations'
    id = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id = mapped_column(String(36), ForeignKey('tenants.id'), index=True)
    email = mapped_column(String(254), nullable=False)
    role = mapped_column(String(20), nullable=False)
    token_hash = mapped_column(String(64), unique=True)
    expires_at = mapped_column(Timestamp, nullable=False)
    used_at = mapped_column(Timestamp, nullable=True)


class Integration(Base):
    __tablename__ = 'integrations'
    __table_args__ = (UniqueConstraint('tenant_id', 'kind'),)
    id = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id = mapped_column(String(36), ForeignKey('tenants.id'), index=True)
    kind = mapped_column(String(30), nullable=False)
    config_encrypted = mapped_column(Text, nullable=False)
    enabled = mapped_column(Boolean, default=False)
    last_run = mapped_column(Timestamp, nullable=True)
    last_status = mapped_column(String(255), nullable=True)


class MailImport(Base):
    __tablename__ = 'mail_imports'
    __table_args__ = (UniqueConstraint('integration_id', 'message_key'),)
    id = mapped_column(String(36), primary_key=True, default=uid)
    integration_id = mapped_column(String(36), ForeignKey('integrations.id'))
    message_key = mapped_column(String(255), nullable=False)


class Setting(Base):
    __tablename__ = 'settings'
    key = mapped_column(String(100), primary_key=True)
    value = mapped_column(Text, nullable=False)


class Domain(Base):
    __tablename__ = 'domains'
    host = mapped_column(String(253), primary_key=True)
    tenant_id = mapped_column(String(36), ForeignKey('tenants.id'), nullable=True)


class Audit(Base):
    __tablename__ = 'audit'
    id = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id = mapped_column(String(36), nullable=True, index=True)
    actor_id = mapped_column(String(36), nullable=True)
    action = mapped_column(String(100), nullable=False)
    detail = mapped_column(String(255), default='')
    created_at = mapped_column(Timestamp, default=now, index=True)


def get_db():
    with SessionLocal() as db:
        yield db


class AuthAttempt(Base):
    __tablename__ = 'auth_attempts'
    key = mapped_column(String(64), primary_key=True)
    count = mapped_column(Integer, default=0)
    reset_at = mapped_column(Timestamp, nullable=False)


class CalendarSync(Base):
    __tablename__ = 'calendar_sync'
    __table_args__ = (UniqueConstraint('integration_id', 'document_id'),)
    id = mapped_column(String(36), primary_key=True, default=uid)
    integration_id = mapped_column(String(36), ForeignKey('integrations.id'))
    document_id = mapped_column(String(36), ForeignKey('documents.id'))


class FolderImport(Base):
    __tablename__ = 'folder_imports'
    __table_args__ = (UniqueConstraint('integration_id', 'source_key'),)
    id = mapped_column(String(36), primary_key=True, default=uid)
    integration_id = mapped_column(String(36), ForeignKey('integrations.id'), nullable=False, index=True)
    tenant_id = mapped_column(String(36), ForeignKey('tenants.id'), nullable=False)
    source_key = mapped_column(String(64), nullable=False)
    filename = mapped_column(String(255), nullable=False)
    document_id = mapped_column(String(36), ForeignKey('documents.id'), nullable=True)
    action = mapped_column(String(20), default='delete', nullable=False)
    status = mapped_column(String(20), default='pending', nullable=False)
    error = mapped_column(String(255), nullable=True)
    updated_at = mapped_column(Timestamp, default=now, nullable=False)


class DocumentVersion(Base):
    __tablename__ = 'document_versions'
    __table_args__ = (UniqueConstraint('document_id', 'number'),)
    id = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id = mapped_column(String(36), ForeignKey('tenants.id'), nullable=False, index=True)
    document_id = mapped_column(String(36), ForeignKey('documents.id'), nullable=False, index=True)
    number = mapped_column(Integer, nullable=False)
    filename = mapped_column(String(255), nullable=False)
    mime = mapped_column(String(100), nullable=False)
    size = mapped_column(BigInteger, nullable=False)
    sha256 = mapped_column(String(64), nullable=False)
    uploader_id = mapped_column(String(36), ForeignKey('users.id'), nullable=True)
    note = mapped_column(String(255), default='', nullable=False)
    created_at = mapped_column(Timestamp, default=now, nullable=False)


class FolderGrant(Base):
    __tablename__ = 'folder_grants'
    __table_args__ = (UniqueConstraint('folder_id', 'user_id'),)
    id = mapped_column(String(36), primary_key=True, default=uid)
    folder_id = mapped_column(String(36), ForeignKey('folders.id'), nullable=False)
    user_id = mapped_column(String(36), ForeignKey('users.id'), nullable=False)
    can_edit = mapped_column(Boolean, default=False, nullable=False)


class DocumentGrant(Base):
    __tablename__ = 'document_grants'
    __table_args__ = (UniqueConstraint('document_id', 'user_id'),)
    id = mapped_column(String(36), primary_key=True, default=uid)
    document_id = mapped_column(String(36), ForeignKey('documents.id'), nullable=False)
    user_id = mapped_column(String(36), ForeignKey('users.id'), nullable=False)
    can_edit = mapped_column(Boolean, default=False, nullable=False)


class Review(Base):
    __tablename__ = 'reviews'
    id = mapped_column(String(36), primary_key=True, default=uid)
    tenant_id = mapped_column(String(36), ForeignKey('tenants.id'), nullable=False, index=True)
    document_id = mapped_column(String(36), ForeignKey('documents.id'), nullable=False, index=True)
    version = mapped_column(Integer, nullable=False)
    requester_id = mapped_column(String(36), ForeignKey('users.id'), nullable=False)
    reviewer_id = mapped_column(String(36), ForeignKey('users.id'), nullable=False)
    status = mapped_column(String(20), default='pending', nullable=False)
    note = mapped_column(String(1000), default='', nullable=False)
    created_at = mapped_column(Timestamp, default=now, nullable=False)
    decided_at = mapped_column(Timestamp, nullable=True)


class UserMFA(Base):
    __tablename__ = 'user_mfa'
    user_id = mapped_column(String(36), ForeignKey('users.id'), primary_key=True)
    enabled = mapped_column(Boolean, default=False, nullable=False)
    secret_encrypted = mapped_column(Text, nullable=False)
    pending_until = mapped_column(Timestamp, nullable=True)
    last_counter = mapped_column(BigInteger, default=-1, nullable=False)
    recovery_hashes = mapped_column(JSON, default=list, nullable=False)


class MFAChallenge(Base):
    __tablename__ = 'mfa_challenges'
    token_hash = mapped_column(String(64), primary_key=True)
    user_id = mapped_column(String(36), ForeignKey('users.id'), nullable=False)
    expires_at = mapped_column(Timestamp, nullable=False)
    attempts = mapped_column(Integer, default=0, nullable=False)
