#!/usr/bin/env python3
"""
generate-data-inventory.py — auto-generate a first-draft data inventory CSV
from ORM model definitions in your codebase.

Supports:
  • SQLAlchemy (Python) — Column() definitions in models.py / database.py
  • Django ORM (Python) — models.Model subclasses
  • Prisma (TypeScript/JavaScript) — schema.prisma
  • TypeORM (TypeScript) — @Entity / @Column decorators
  • ActiveRecord (Ruby) — migration add_column / create_table

Usage:
  python3 scripts/generate-data-inventory.py [directory] [--output FILE]
  python3 scripts/generate-data-inventory.py backend/src --output docs/data-inventory.csv
  python3 scripts/generate-data-inventory.py . --output docs/data-inventory.md --format md
"""

import argparse
import csv
import io
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── PII heuristics ────────────────────────────────────────────────────────────

CRITICAL_PATTERNS = [
    r'\bssn\b', r'\bsin\b', r'\bcpf\b', r'\bcnpj\b', r'\btax_id\b', r'\btin\b',
    r'\bpassport\b', r'\bdrivers?_licen[cs]e\b',
    r'\bcredit_card\b', r'\bcard_number\b', r'\bcvv\b', r'\bcvc\b',
    r'\biban\b', r'\brouting_number\b', r'\baccount_number\b',
    r'\bbiometric\b', r'\bfingerprint\b', r'\bface_id\b', r'\bretina\b',
    r'\bsignature_image\b', r'\bsignature_data\b',
    r'\bhealth\b', r'\bmedical\b', r'\bdiagnosis\b', r'\bprescription\b',
    r'\bgenetic\b', r'\bdna\b',
    r'\bpassword\b', r'\bpassword_hash\b', r'\bpwd\b',
]

HIGH_PATTERNS = [
    r'\bemail\b', r'\be_mail\b',
    r'\bphone\b', r'\bmobile\b', r'\bcell\b', r'\btelephone\b',
    r'\bfull_name\b', r'\blegal_name\b', r'\bfirst_name\b', r'\blast_name\b',
    r'\bfirstname\b', r'\blastname\b', r'\bsurname\b', r'\bgiven_name\b',
    r'\baddress\b', r'\bstreet\b', r'\baddress_line\b',
    r'\bzip\b', r'\bzip_code\b', r'\bpostal_code\b', r'\bpostcode\b',
    r'\bip_address\b', r'\bip_addr\b', r'\bclient_ip\b', r'\bremote_addr\b',
    r'\buser_agent\b', r'\bdevice_id\b', r'\bdevice_fingerprint\b',
    r'\bgps\b', r'\blatitude\b', r'\blongitude\b', r'\bgeo\b', r'\blocation\b',
    r'\bdate_of_birth\b', r'\bdob\b', r'\bbirthdate\b', r'\bbirthday\b',
    r'\bsex\b', r'\bgender\b',
    r'\brace\b', r'\bethnicity\b', r'\bnationality\b',
    r'\breligion\b', r'\bpolitical\b',
    r'\bsexual_orientation\b',
    r'\btoken\b', r'\bauth_token\b', r'\baccess_token\b', r'\brefresh_token\b',
    r'\bapi_key\b', r'\bsecret\b',
    r'\bsignature\b', r'\bsigned\b',
    r'\bw9\b', r'\btax_form\b',
]

MEDIUM_PATTERNS = [
    r'\busername\b', r'\buser_name\b', r'\bhandle\b',
    r'\bcity\b', r'\bstate\b', r'\bcountry\b', r'\bregion\b',
    r'\bpurchase\b', r'\border\b', r'\btransaction\b',
    r'\bpayment_method\b', r'\bpayment_option\b',
    r'\bsession_id\b', r'\bcookie\b',
    r'\btrack\b', r'\bactivity\b', r'\bbehavior\b',
    r'\bnotes?\b', r'\bcomments?\b', r'\bdescription\b',  # may contain PII
    r'\bprofile\b', r'\bavatar\b', r'\bphoto\b', r'\bimage\b',
]

LEGAL_BASIS_SUGGESTIONS = {
    'CRITICAL': 'Explicit consent (Art. 9 GDPR / Art. 11 LGPD) or legal obligation',
    'HIGH':     'Consent, contract, or legitimate interest (GDPR Art. 6 / LGPD Art. 7)',
    'MEDIUM':   'Contract or legitimate interest (GDPR Art. 6(1)(b)/(f) / LGPD Art. 7)',
    'LOW':      'Legitimate interest or contract performance',
}

RETENTION_SUGGESTIONS = {
    'CRITICAL': 'Define minimal retention; delete on account closure; document legal hold exceptions',
    'HIGH':     'Define retention per purpose; anonymise or delete when purpose expires',
    'MEDIUM':   'Define retention; review annually',
    'LOW':      'Standard operational retention',
}


def classify_field(field_name: str) -> str:
    name = field_name.lower()
    for pat in CRITICAL_PATTERNS:
        if re.search(pat, name):
            return 'CRITICAL'
    for pat in HIGH_PATTERNS:
        if re.search(pat, name):
            return 'HIGH'
    for pat in MEDIUM_PATTERNS:
        if re.search(pat, name):
            return 'MEDIUM'
    return 'LOW'


# ── parsers ────���──────────────────────��───────────────────────────────────────

@dataclass
class FieldRecord:
    source_file: str
    table: str
    field: str
    data_type: str
    sensitivity: str
    pii_category: str
    legal_basis: str
    encrypted: str
    retention_policy: str
    notes: str = ''


def pii_category_label(sensitivity: str, field_name: str) -> str:
    name = field_name.lower()
    if any(re.search(p, name) for p in [r'\bemail\b']):
        return 'Email address'
    if any(re.search(p, name) for p in [r'\bphone\b', r'\bmobile\b']):
        return 'Phone number'
    if any(re.search(p, name) for p in [r'\bfull_name\b', r'\blegal_name\b', r'\bfirst_name\b', r'\blast_name\b']):
        return 'Full name'
    if any(re.search(p, name) for p in [r'\baddress\b', r'\bstreet\b', r'\bzip\b', r'\bpostal\b']):
        return 'Physical address'
    if any(re.search(p, name) for p in [r'\bssn\b', r'\bcpf\b', r'\btax_id\b', r'\btin\b']):
        return 'Government/tax ID — CRITICAL'
    if any(re.search(p, name) for p in [r'\bpassword\b', r'\btoken\b', r'\bsecret\b', r'\bapi_key\b']):
        return 'Auth credential'
    if any(re.search(p, name) for p in [r'\bsignature\b', r'\bbiometric\b', r'\bfingerprint\b']):
        return 'Biometric data (GDPR Art. 9 / LGPD Art. 11)'
    if any(re.search(p, name) for p in [r'\bhealth\b', r'\bmedical\b', r'\bdiagnosis\b']):
        return 'Health data (GDPR Art. 9 / LGPD Art. 11)'
    if any(re.search(p, name) for p in [r'\bip_address\b', r'\bip_addr\b', r'\buser_agent\b']):
        return 'Online identifier'
    if any(re.search(p, name) for p in [r'\blocation\b', r'\bgps\b', r'\blatitude\b', r'\blongitude\b']):
        return 'Geolocation'
    if sensitivity in ('CRITICAL', 'HIGH'):
        return 'Personal data'
    if sensitivity == 'MEDIUM':
        return 'Potentially personal'
    return 'Non-personal / operational'


def is_encrypted_hint(field_name: str, field_type: str) -> str:
    name = field_name.lower()
    typ = field_type.lower()
    if 'encrypted' in name or 'hash' in name or 'hashed' in name:
        return 'Yes (field name suggests encryption/hash)'
    if any(x in typ for x in ['bytea', 'binary', 'blob', 'text']) and 'encrypt' in name:
        return 'Yes'
    return 'Review required'


def make_record(source_file: str, table: str, field: str, data_type: str) -> FieldRecord:
    sensitivity = classify_field(field)
    return FieldRecord(
        source_file=source_file,
        table=table,
        field=field,
        data_type=data_type,
        sensitivity=sensitivity,
        pii_category=pii_category_label(sensitivity, field),
        legal_basis=LEGAL_BASIS_SUGGESTIONS[sensitivity],
        encrypted=is_encrypted_hint(field, data_type),
        retention_policy=RETENTION_SUGGESTIONS[sensitivity],
    )


# ── SQLAlchemy parser ─────────────────────────────────────────────────────────

def parse_sqlalchemy(path: Path) -> list[FieldRecord]:
    records = []
    content = path.read_text(errors='replace')

    # Find class definitions that look like DB models
    class_blocks = re.split(r'\nclass\s+', content)
    for block in class_blocks[1:]:
        class_match = re.match(r'(\w+)\s*\(', block)
        if not class_match:
            continue
        class_name = class_match.group(1)

        # Derive table name from __tablename__ or snake_case class name
        tn_match = re.search(r'__tablename__\s*=\s*[\'"]([^\'"]+)[\'"]', block)
        table = tn_match.group(1) if tn_match else re.sub(r'(?<!^)(?=[A-Z])', '_', class_name).lower()

        # Find Column definitions
        for col_match in re.finditer(
            r'(\w+)\s*(?::\s*\w+\s*)?=\s*(?:mapped_column|Column)\s*\(\s*([^,)]+)',
            block
        ):
            field_name = col_match.group(1)
            col_type = col_match.group(2).strip()
            if field_name.startswith('_') or field_name in ('metadata', 'query'):
                continue
            records.append(make_record(str(path), table, field_name, col_type))

    return records


# ── Django ORM parser ──────────────���──────────────────────────────────────────

DJANGO_FIELD_RE = re.compile(
    r'^\s{4}(\w+)\s*=\s*models\.(\w+Field[^(]*)\(',
    re.MULTILINE
)

def parse_django(path: Path) -> list[FieldRecord]:
    records = []
    content = path.read_text(errors='replace')
    class_blocks = re.split(r'\nclass\s+', content)
    for block in class_blocks[1:]:
        class_match = re.match(r'(\w+)\s*\(', block)
        if not class_match:
            continue
        class_name = class_match.group(1)
        if 'models.Model' not in block and 'Model' not in block:
            continue
        table_match = re.search(r'db_table\s*=\s*[\'"]([^\'"]+)[\'"]', block)
        table = table_match.group(1) if table_match else \
            re.sub(r'(?<!^)(?=[A-Z])', '_', class_name).lower()
        for m in DJANGO_FIELD_RE.finditer(block):
            records.append(make_record(str(path), table, m.group(1), m.group(2)))
    return records


# ── Prisma parser ─────────────────────────────────────────────────────────────

def parse_prisma(path: Path) -> list[FieldRecord]:
    records = []
    content = path.read_text(errors='replace')
    model_blocks = re.split(r'\bmodel\s+', content)
    for block in model_blocks[1:]:
        model_match = re.match(r'(\w+)\s*\{', block)
        if not model_match:
            continue
        table = model_match.group(1)
        brace_end = block.find('}')
        body = block[:brace_end] if brace_end != -1 else block
        for line in body.splitlines():
            field_match = re.match(r'\s+(\w+)\s+(\w[\w?[\]]*)', line.strip())
            if field_match and not line.strip().startswith('//') \
                    and not line.strip().startswith('@@'):
                records.append(make_record(
                    str(path), table,
                    field_match.group(1),
                    field_match.group(2)
                ))
    return records


# ── TypeORM parser ────────────────────────────────────────────────────────────

def parse_typeorm(path: Path) -> list[FieldRecord]:
    records = []
    content = path.read_text(errors='replace')
    entity_blocks = re.split(r'@Entity', content)
    for block in entity_blocks[1:]:
        table_match = re.search(r'[\'"](\w+)[\'"]', block[:60])
        class_match = re.search(r'class\s+(\w+)', block[:200])
        if not class_match:
            continue
        table = table_match.group(1) if table_match else \
            re.sub(r'(?<!^)(?=[A-Z])', '_', class_match.group(1)).lower()
        for col_match in re.finditer(
            r'@Column[^)]*\)\s*\n\s*(\w+)(?:\??):\s*([\w|]+)',
            block
        ):
            records.append(make_record(str(path), table, col_match.group(1), col_match.group(2)))
    return records


# ── ActiveRecord (Ruby migration) parser ─────────────────────────────────────

def parse_activerecord(path: Path) -> list[FieldRecord]:
    records = []
    content = path.read_text(errors='replace')
    # create_table "users" do / add_column :users, :email
    for tbl_match in re.finditer(r'create_table\s+[\'"](\w+)[\'"]', content):
        table = tbl_match.group(1)
        # Find the block following create_table
        start = tbl_match.end()
        end = content.find('end', start)
        block = content[start:end] if end != -1 else content[start:start+2000]
        for col_match in re.finditer(r't\.(\w+)\s+[\'"]?(\w+)[\'"]?', block):
            col_type, col_name = col_match.group(1), col_match.group(2)
            if col_name in ('null', 'default', 'index', 'unique'):
                continue
            records.append(make_record(str(path), table, col_name, col_type))
    for col_match in re.finditer(
        r'add_column\s+:(\w+)\s*,\s*:(\w+)\s*,\s*:(\w+)', content
    ):
        records.append(make_record(str(path), col_match.group(1), col_match.group(2), col_match.group(3)))
    return records


# ── file routing ───��──────────────────────────────────────────────────────────

def parse_file(path: Path) -> list[FieldRecord]:
    name = path.name.lower()
    suffix = path.suffix.lower()
    try:
        if suffix == '.py':
            content = path.read_text(errors='replace')
            if 'models.Model' in content or 'django' in content.lower():
                return parse_django(path)
            if 'Column(' in content or 'mapped_column(' in content:
                return parse_sqlalchemy(path)
        elif name == 'schema.prisma' or name.endswith('.prisma'):
            return parse_prisma(path)
        elif suffix in ('.ts', '.tsx') and ('@Entity' in path.read_text(errors='replace')):
            return parse_typeorm(path)
        elif suffix == '.rb' and ('create_table' in path.read_text(errors='replace') or
                                  'add_column' in path.read_text(errors='replace')):
            return parse_activerecord(path)
    except Exception as e:
        print(f"Warning: could not parse {path}: {e}", file=sys.stderr)
    return []


# ── output ────────────────────────────────────────────────────────────────────

HEADERS = [
    'Source File', 'Table / Model', 'Field', 'Data Type',
    'Sensitivity', 'PII Category', 'Legal Basis (suggested)',
    'Encrypted?', 'Retention Policy (suggested)', 'Notes'
]


def write_csv(records: list[FieldRecord], output) -> None:
    writer = csv.writer(output)
    writer.writerow(HEADERS)
    for r in records:
        writer.writerow([
            r.source_file, r.table, r.field, r.data_type,
            r.sensitivity, r.pii_category, r.legal_basis,
            r.encrypted, r.retention_policy, r.notes
        ])


def write_markdown(records: list[FieldRecord], output) -> None:
    output.write('# Data Inventory\n\n')
    output.write('> Auto-generated by `scripts/generate-data-inventory.py`. Review and complete each row.\n\n')
    output.write('| ' + ' | '.join(HEADERS) + ' |\n')
    output.write('|' + '---|' * len(HEADERS) + '\n')
    for r in records:
        row = [
            r.source_file, r.table, r.field, r.data_type,
            r.sensitivity, r.pii_category, r.legal_basis,
            r.encrypted, r.retention_policy, r.notes
        ]
        output.write('| ' + ' | '.join(row) + ' |\n')


# ── main ────────────────────────────────────��─────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('directory', nargs='?', default='.', help='Root directory to scan')
    parser.add_argument('--output', '-o', help='Output file path (default: stdout)')
    parser.add_argument('--format', '-f', choices=['csv', 'md'], default='csv')
    args = parser.parse_args()

    root = Path(args.directory)
    if not root.is_dir():
        print(f"Error: '{root}' is not a directory", file=sys.stderr)
        sys.exit(2)

    SKIP_DIRS = {
        'node_modules', '.venv', 'venv', '.git', '__pycache__',
        'dist', 'build', '.next', '.nuxt', 'vendor', 'migrations'
    }

    records: list[FieldRecord] = []
    for path in root.rglob('*'):
        if path.is_file() and not any(part in SKIP_DIRS for part in path.parts):
            records.extend(parse_file(path))

    # Sort by sensitivity then table
    order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    records.sort(key=lambda r: (order.get(r.sensitivity, 9), r.table, r.field))

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, 'w', newline='', encoding='utf-8') as f:
            if args.format == 'md':
                write_markdown(records, f)
            else:
                write_csv(records, f)
        print(f"Data inventory written to {out_path} ({len(records)} fields)", file=sys.stderr)
    else:
        out = io.StringIO()
        if args.format == 'md':
            write_markdown(records, out)
        else:
            write_csv(records, out)
        print(out.getvalue())

    # Summary
    from collections import Counter
    counts = Counter(r.sensitivity for r in records)
    print(f"\nSummary: {counts.get('CRITICAL',0)} CRITICAL  "
          f"{counts.get('HIGH',0)} HIGH  "
          f"{counts.get('MEDIUM',0)} MEDIUM  "
          f"{counts.get('LOW',0)} LOW", file=sys.stderr)


if __name__ == '__main__':
    main()
