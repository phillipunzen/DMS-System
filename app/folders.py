"""Logical folder paths, generated from metadata without touching archive paths."""
import hashlib
import re
import unicodedata
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from .db import Folder, Audit
from .naming import FIELDS, PLACEHOLDER, INVALID, RESERVED, safe_part, truncate, template_values

MAX_DEPTH = 8


def validate_folder_template(value):
    if not value or not value.strip():
        return None
    value = value.strip()
    parts = value.split('/')
    if len(parts) > MAX_DEPTH or any(not p.strip() or p.strip() in {'.', '..'} for p in parts):
        raise ValueError('Ordner-Vorlagen brauchen 1 bis 8 Ebenen, getrennt mit /; keine leeren Ebenen oder . bzw. ...')
    for part in parts:
        if any(unicodedata.category(c).startswith('C') for c in part) or INVALID.search(part):
            raise ValueError('Ordnernamen dürfen keine Steuerzeichen oder Zeichen \\ : * ? " < > | enthalten.')
        if any(f not in FIELDS for f in PLACEHOLDER.findall(part)) or re.search(r'[{}]', PLACEHOLDER.sub('x', part)):
            raise ValueError('Unbekannter Platzhalter in der Ordner-Vorlage.')
        if not safe_part(PLACEHOLDER.sub('x', part)):
            raise ValueError('Jede Ebene muss einen Ordnernamen ergeben.')
    return '/'.join(p.strip() for p in parts)


def folder_depth(db, folder):
    depth, seen = 0, set()
    while folder:
        if folder.id in seen:
            raise ValueError('Ungültige Ordnerstruktur.')
        seen.add(folder.id); depth += 1
        folder = db.get(Folder, folder.parent_id) if folder.parent_id else None
    return depth


def render_folder_parts(db, doc, template):
    values = template_values(db, doc)
    if any(values[f] is None or not safe_part(values[f]) for f in PLACEHOLDER.findall(template)):
        return None
    parts = []
    for part in template.split('/'):
        rendered = safe_part(PLACEHOLDER.sub(lambda m: safe_part(values[m[1]]), part))
        if not rendered:
            return None
        if RESERVED.match(rendered):
            rendered = '_' + rendered
        # Keep long names distinct, including multibyte metadata, within the path index limit.
        if len(rendered.encode()) > 80:
            rendered = truncate(rendered, 67) + '-' + hashlib.sha256(rendered.encode()).hexdigest()[:12]
        parts.append(rendered)
    return parts


def resolve_rule_folder(db, doc, rule, allowed=None, actor_id=None):
    base = db.get(Folder, rule.folder_id) if rule.folder_id else None
    if base and base.tenant_id != doc.tenant_id:
        return None
    if not rule.folder_template:
        return base
    parts = render_folder_parts(db, doc, rule.folder_template)
    if not parts or folder_depth(db, base) + len(parts) > MAX_DEPTH:
        return None
    plan, prefix = [], base.name if base else ''
    parent_id, missing_parent = base.id if base else None, False
    for part in parts:
        name = prefix + '/' + part if prefix else part
        if len(name) > 700:
            return None
        # Use the stored spelling on case-insensitive database collations.
        folder = db.scalar(select(Folder).where(Folder.tenant_id == doc.tenant_id, Folder.name == name))
        if folder and (missing_parent or folder.parent_id != parent_id or (allowed and not allowed(folder.id))):
            return None
        plan.append((part, folder))
        prefix = folder.name if folder else name
        parent_id = folder.id if folder else None
        missing_parent = missing_parent or folder is None
    # The whole existing path is authorized before creating or changing anything.
    parent = base
    for part, folder in plan:
        name = parent.name + '/' + part if parent else part
        if not folder:
            try:
                with db.begin_nested():
                    folder = Folder(tenant_id=doc.tenant_id, name=name, parent_id=parent.id if parent else None,
                        color=base.color if base else 'green')
                    db.add(folder); db.flush()
                db.add(Audit(tenant_id=doc.tenant_id, actor_id=actor_id, action='folder.created', detail=name[:255]))
            except IntegrityError:
                # Another import may have created the same tenant-local folder meanwhile.
                folder = db.scalar(select(Folder).where(Folder.tenant_id == doc.tenant_id, Folder.name == name))
                if not folder or folder.parent_id != (parent.id if parent else None) or (allowed and not allowed(folder.id)):
                    return None
        parent = folder
    return parent
