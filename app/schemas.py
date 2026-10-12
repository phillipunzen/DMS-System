from datetime import date
from typing import Literal
from pydantic import BaseModel, Field, EmailStr, field_validator, model_validator
from .naming import validate_template

Role = Literal['viewer', 'editor', 'manager', 'owner']
class LoginInput(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    method: Literal['local', 'ldap'] = 'local'
class RegisterInput(BaseModel):
    email: EmailStr
    name: str = Field(min_length=1, max_length=150)
    password: str = Field(min_length=12, max_length=256)
class TenantInput(BaseModel):
    name: str = Field(min_length=1, max_length=150)
class FolderInput(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    color: Literal['green', 'blue', 'orange', 'purple'] = 'green'
class DocInput(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    folder_id: str | None = None
    supplier: str = Field(default='', max_length=150)
    doc_type: str = Field(default='Sonstiges', max_length=100)
    tags: list[str] = Field(default_factory=list, max_length=20)
    amount: str | None = Field(default=None, pattern=r'^\d{1,12}([.,]\d{1,2})?$')
    due_date: date | None = None
    paid: bool = False
class RuleInput(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    field: Literal['all', 'text', 'supplier', 'doc_type', 'title', 'filename']
    contains: str = Field(default='', max_length=150)
    folder_id: str | None = None
    filename_template: str | None = Field(default=None, max_length=255)
    priority: int = Field(default=100, ge=0, le=9999)
    enabled: bool = True

    @field_validator('filename_template')
    @classmethod
    def valid_template(cls, value):
        return validate_template(value)

    @model_validator(mode='after')
    def valid_rule(self):
        self.contains = self.contains.strip() if self.field != 'all' else ''
        self.folder_id = self.folder_id or None
        if self.field != 'all' and not self.contains:
            raise ValueError('Geben Sie einen Suchtext für die Bedingung ein.')
        if not self.folder_id and not self.filename_template:
            raise ValueError('Wählen Sie einen Zielordner oder geben Sie eine Namensvorlage ein.')
        return self
class InviteInput(BaseModel):
    email: EmailStr
    role: Literal['viewer', 'editor', 'manager']
class AcceptInput(BaseModel):
    token: str
    name: str = Field(default='', max_length=150)
    password: str = Field(default='', max_length=256)
class RoleInput(BaseModel):
    role: Role
class PasswordInput(BaseModel):
    current_password: str
    password: str = Field(min_length=12, max_length=256)
class IntegrationInput(BaseModel):
    enabled: bool = False
    config: dict
class SettingsInput(BaseModel):
    app_name: str = Field(min_length=1, max_length=80)
    registration_enabled: bool = False
    tenant_creation_enabled: bool = True
    ai_external_blocked: bool | None = None
class DomainInput(BaseModel):
    host: str = Field(min_length=1, max_length=253, pattern=r'^[A-Za-z0-9.-]+$')
    tenant_id: str | None = None
class QuotaInput(BaseModel):
    quota_mb: int = Field(ge=1, le=100000000)

class CodexTenantsInput(BaseModel):
    tenant_ids: list[str] = Field(default_factory=list, max_length=10000)

class AIPreviewInput(BaseModel):
    text: str | None = Field(default=None, max_length=10000)

class AIReviewInput(BaseModel):
    text: str = Field(min_length=1, max_length=10000)
    token: str = Field(min_length=1, max_length=100)
    confirmed: Literal[True]
