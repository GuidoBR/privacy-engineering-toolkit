#!/usr/bin/env python3
"""
scan-iac.py — deterministic privacy and security checks for Infrastructure-as-Code files.

Parses Terraform (.tf), CloudFormation (.yml / .json), and CDK TypeScript (.ts)
and evaluates binary flags that the LLM should not guess at: encryption, public
access, log retention, key rotation, PITR, autovacuum, IAM wildcards, etc.

These checks are fully deterministic given the source file. This script is
designed to be run by the privacy-audit skill so the LLM receives structured
findings rather than grepping and interpreting raw IaC output itself.

Usage:
  python3 scripts/scan-iac.py [directory] [options]

Options:
  -d, --dir DIR        Directory to scan (default: current directory)
  -f, --format FORMAT  Output format: text (default), json, sarif
  -q, --quiet          Only print findings, no header
  -h, --help           Show this help

Exit codes:
  0  No findings
  1  Findings detected
  2  Script error
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── Finding dataclass ─────────────────────────────────────────────────────────

@dataclass
class Finding:
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    rule_id: str
    title: str
    detail: str
    file: str
    line: int
    regulation: str = ''


# ── Terraform parser ──────────────────────────────────────────────────────────

def extract_tf_blocks(content: str) -> list[dict]:
    """
    Extract top-level resource/data blocks from Terraform HCL.
    Returns list of dicts: {type, name, label, start_line, body}
    This is regex-based and handles single-level nesting well enough
    for attribute extraction. Does not parse nested blocks perfectly.
    """
    blocks = []
    # Match: resource "aws_db_instance" "main" {
    block_header = re.compile(
        r'^(resource|data)\s+"([^"]+)"\s+"([^"]+)"\s*\{',
        re.MULTILINE
    )
    for m in block_header.finditer(content):
        block_type = m.group(2)
        block_name = m.group(3)
        start_line = content[:m.start()].count('\n') + 1
        # Find matching closing brace (simple depth counter)
        depth = 0
        body_start = m.end()
        body_end = body_start
        for i, ch in enumerate(content[body_start:], body_start):
            if ch == '{':
                depth += 1
            elif ch == '}':
                if depth == 0:
                    body_end = i
                    break
                depth -= 1
        body = content[body_start:body_end]
        blocks.append({
            'resource_type': block_type_canonical(block_type, m.group(1)),
            'name': block_name,
            'start_line': start_line,
            'body': body,
            'file': '',  # filled in by caller
        })
    return blocks


def block_type_canonical(resource_type: str, keyword: str) -> str:
    return resource_type


def attr(body: str, key: str) -> Optional[str]:
    """Extract the value of a top-level attribute from a Terraform block body."""
    m = re.search(
        r'^\s*' + re.escape(key) + r'\s*=\s*(.+)$',
        body, re.MULTILINE
    )
    return m.group(1).strip().strip('"').strip("'") if m else None


def has_block(body: str, name: str) -> bool:
    """Return True if a named nested block exists in the body."""
    return bool(re.search(r'^\s*' + re.escape(name) + r'\s*\{', body, re.MULTILINE))


def is_false(value: Optional[str]) -> bool:
    return value is not None and value.lower() in ('false', '0', 'null')


def is_true(value: Optional[str]) -> bool:
    return value is not None and value.lower() in ('true', '1')


def is_variable_ref(value: Optional[str]) -> bool:
    """Return True when the value is a Terraform expression, not a literal.

    var.x, module.x, local.x, data.x, each.x are indeterminate at parse time.
    A check that passes because the value is var.enable_encryption may still
    fail at apply-time if the variable's default is false.
    """
    if value is None:
        return False
    return bool(re.match(r'^(var|module|local|data|each|path|self)\b', value.strip()))


def check_terraform(path: Path) -> list[Finding]:
    content = path.read_text(errors='replace')
    findings = []
    blocks = extract_tf_blocks(content)

    # Track S3 buckets so we can check for companion public-access-block resources
    s3_buckets: set[str] = set()
    s3_public_blocked: set[str] = set()
    s3_encrypted: set[str] = set()

    for blk in blocks:
        blk['file'] = str(path)
        rt = blk['resource_type']
        body = blk['body']
        ln = blk['start_line']
        name = blk['name']

        # ── RDS / Aurora ────────────────────────────────────────────────────
        if rt in ('aws_db_instance', 'aws_rds_cluster', 'aws_rds_cluster_instance'):
            enc = attr(body, 'storage_encrypted')
            if enc is None or is_false(enc):
                findings.append(Finding(
                    'CRITICAL', 'rds-encryption-disabled',
                    f'RDS encryption at rest not enabled ({name})',
                    'storage_encrypted must be true. Unencrypted PII on disk.',
                    str(path), ln,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))
            elif is_variable_ref(enc):
                findings.append(Finding(
                    'LOW', 'rds-encryption-variable-ref',
                    f'RDS storage_encrypted is a variable reference — verify actual value ({name})',
                    f'Value is `{enc}`. Confirm the variable default and all call-site overrides '
                    f'are `true`. A false default silently disables encryption at rest.',
                    str(path), ln,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))

            pub = attr(body, 'publicly_accessible')
            if pub is None or is_true(pub):
                findings.append(Finding(
                    'CRITICAL', 'rds-publicly-accessible',
                    f'RDS instance publicly accessible ({name})',
                    'publicly_accessible must be false. Database is reachable from the internet.',
                    str(path), ln,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))
            elif is_variable_ref(pub):
                findings.append(Finding(
                    'LOW', 'rds-public-access-variable-ref',
                    f'RDS publicly_accessible is a variable reference — verify actual value ({name})',
                    f'Value is `{pub}`. Confirm default and all overrides are `false`.',
                    str(path), ln,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))

            backup = attr(body, 'backup_retention_period')
            if backup is not None and backup in ('0', ''):
                findings.append(Finding(
                    'HIGH', 'rds-no-backup-retention',
                    f'RDS automated backups disabled ({name})',
                    'backup_retention_period = 0 disables automated backups.',
                    str(path), ln,
                    'GDPR Art. 32'
                ))

            if rt == 'aws_db_instance':
                dp = attr(body, 'deletion_protection')
                if dp is None or is_false(dp):
                    findings.append(Finding(
                        'MEDIUM', 'rds-no-deletion-protection',
                        f'RDS deletion protection not enabled ({name})',
                        'deletion_protection should be true in production to prevent accidental loss.',
                        str(path), ln,
                        'GDPR Art. 32'
                    ))

        # ── RDS Parameter Group — check autovacuum ──────────────────────────
        if rt == 'aws_db_parameter_group':
            if 'autovacuum' in body and 'autovacuum_enabled' in body:
                av = re.search(r'autovacuum_enabled["\s]*[,:]?\s*["\']?(off|false|0)["\']?', body, re.IGNORECASE)
                if av:
                    findings.append(Finding(
                        'MEDIUM', 'rds-autovacuum-disabled',
                        f'PostgreSQL autovacuum disabled in parameter group ({name})',
                        'autovacuum_enabled=off means deleted PII rows are not physically reclaimed. '
                        'MVCC dead tuples retain personal data on disk after logical deletion.',
                        str(path), ln,
                        'GDPR Art. 17 / LGPD Art. 18(VI)'
                    ))

        # ── S3 ──────────────────────────────────────────────────────────────
        if rt == 'aws_s3_bucket':
            s3_buckets.add(name)

        if rt == 'aws_s3_bucket_public_access_block':
            bucket_ref = attr(body, 'bucket')
            if bucket_ref:
                # Extract the logical name from aws_s3_bucket.xxx.id references
                ref_match = re.search(r'aws_s3_bucket\.(\w+)', bucket_ref)
                if ref_match:
                    s3_public_blocked.add(ref_match.group(1))
            # Check each block flag
            for flag in ('block_public_acls', 'block_public_policy',
                         'ignore_public_acls', 'restrict_public_buckets'):
                v = attr(body, flag)
                if v is None or is_false(v):
                    findings.append(Finding(
                        'CRITICAL', 's3-public-access-not-fully-blocked',
                        f'S3 public access not fully blocked — {flag} is not true',
                        f'{flag} must be true to prevent public data exposure.',
                        str(path), ln,
                        'GDPR Art. 32 / LGPD Art. 46'
                    ))

        if rt == 'aws_s3_bucket_server_side_encryption_configuration':
            s3_encrypted.add(name)  # presence means encryption configured

        # ── CloudWatch Log Group ────────────────────────────────────────────
        if rt == 'aws_cloudwatch_log_group':
            ret = attr(body, 'retention_in_days')
            if ret is None:
                findings.append(Finding(
                    'HIGH', 'cloudwatch-no-retention',
                    f'CloudWatch log group has no retention period ({name})',
                    'retention_in_days not set — logs are retained indefinitely. '
                    'Violates storage limitation principle if logs contain PII.',
                    str(path), ln,
                    'GDPR Art. 5(1)(e) / LGPD Art. 15'
                ))
            elif ret == '0':
                findings.append(Finding(
                    'HIGH', 'cloudwatch-retention-never-expire',
                    f'CloudWatch log group retention set to never expire ({name})',
                    'retention_in_days = 0 means logs never expire. '
                    'Set a retention period appropriate to the data sensitivity.',
                    str(path), ln,
                    'GDPR Art. 5(1)(e) / LGPD Art. 15'
                ))
            enc_key = attr(body, 'kms_key_id')
            if not enc_key:
                findings.append(Finding(
                    'MEDIUM', 'cloudwatch-no-encryption',
                    f'CloudWatch log group not encrypted with KMS ({name})',
                    'kms_key_id not set — log group uses default encryption, not customer-managed key.',
                    str(path), ln,
                    'GDPR Art. 32'
                ))

        # ── KMS Key ─────────────────────────────────────────────────────────
        if rt == 'aws_kms_key':
            rotation = attr(body, 'enable_key_rotation')
            if rotation is None or is_false(rotation):
                findings.append(Finding(
                    'HIGH', 'kms-rotation-disabled',
                    f'KMS key rotation not enabled ({name})',
                    'enable_key_rotation should be true. Without rotation, a compromised '
                    'key exposes all data encrypted under it indefinitely.',
                    str(path), ln,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))

        # ── SQS Queue ────────────────────────────────────────────────────────
        if rt == 'aws_sqs_queue':
            kms = attr(body, 'kms_master_key_id')
            sqs_enc = attr(body, 'sqs_managed_sse_enabled')
            if not kms and (sqs_enc is None or is_false(sqs_enc)):
                findings.append(Finding(
                    'HIGH', 'sqs-encryption-disabled',
                    f'SQS queue not encrypted ({name})',
                    'Neither kms_master_key_id nor sqs_managed_sse_enabled is set. '
                    'If queue messages contain PII, encryption at rest is required.',
                    str(path), ln,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))

        # ── DynamoDB ─────────────────────────────────────────────────────────
        if rt == 'aws_dynamodb_table':
            if not has_block(body, 'server_side_encryption'):
                findings.append(Finding(
                    'HIGH', 'dynamodb-encryption-disabled',
                    f'DynamoDB table has no server_side_encryption block ({name})',
                    'Add server_side_encryption { enabled = true } or use KMS-managed key.',
                    str(path), ln,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))
            else:
                # Check enabled is not explicitly false inside the block
                sse_match = re.search(r'server_side_encryption\s*\{([^}]+)\}', body, re.DOTALL)
                if sse_match:
                    sse_body = sse_match.group(1)
                    sse_enabled = attr(sse_body, 'enabled')
                    if sse_enabled is not None and is_false(sse_enabled):
                        findings.append(Finding(
                            'HIGH', 'dynamodb-encryption-explicitly-disabled',
                            f'DynamoDB server_side_encryption explicitly disabled ({name})',
                            'server_side_encryption { enabled = false } disables encryption at rest.',
                            str(path), ln,
                            'GDPR Art. 32 / LGPD Art. 46'
                        ))

            if not has_block(body, 'point_in_time_recovery'):
                findings.append(Finding(
                    'MEDIUM', 'dynamodb-no-pitr',
                    f'DynamoDB table has no point_in_time_recovery block ({name})',
                    'PITR should be enabled on tables containing PII for breach recovery capability.',
                    str(path), ln,
                    'GDPR Art. 32'
                ))
            else:
                pitr_match = re.search(r'point_in_time_recovery\s*\{([^}]+)\}', body, re.DOTALL)
                if pitr_match:
                    pitr_enabled = attr(pitr_match.group(1), 'enabled')
                    if pitr_enabled is not None and is_false(pitr_enabled):
                        findings.append(Finding(
                            'MEDIUM', 'dynamodb-pitr-disabled',
                            f'DynamoDB point_in_time_recovery explicitly disabled ({name})',
                            '',
                            str(path), ln,
                            'GDPR Art. 32'
                        ))

        # ── Security Group — open database ports ─────────────────────────────
        if rt in ('aws_security_group', 'aws_security_group_rule'):
            DB_PORTS = {5432: 'PostgreSQL', 3306: 'MySQL', 1433: 'MSSQL',
                        27017: 'MongoDB', 6379: 'Redis', 9200: 'Elasticsearch'}
            # Check for 0.0.0.0/0 or ::/0 on DB ports
            if re.search(r'0\.0\.0\.0/0|::/0', body):
                for port, db_name in DB_PORTS.items():
                    if str(port) in body:
                        findings.append(Finding(
                            'CRITICAL', 'sg-db-port-open-to-internet',
                            f'Security group allows {db_name} (:{port}) from 0.0.0.0/0 ({name})',
                            f'Database port {port} is reachable from the internet. '
                            'Restrict to VPC CIDR or specific security group IDs.',
                            str(path), ln,
                            'GDPR Art. 32 / LGPD Art. 46'
                        ))

        # ── IAM — wildcard actions ───────────────────────────────────────────
        if rt in ('aws_iam_policy', 'aws_iam_role_policy', 'aws_iam_user_policy'):
            if re.search(r'"Action"\s*:\s*"\*"', body) or \
               re.search(r'actions\s*=\s*\[?\s*"\*"', body):
                findings.append(Finding(
                    'HIGH', 'iam-wildcard-action',
                    f'IAM policy uses wildcard Action "*" ({name})',
                    'Wildcard actions violate least-privilege. Scope to specific actions.',
                    str(path), ln,
                    'GDPR Art. 25 / LGPD Art. 49'
                ))

    # ── Post-pass: S3 buckets without a public-access-block resource ─────────
    for bucket_name in s3_buckets:
        if bucket_name not in s3_public_blocked:
            # Find the line number of the bucket resource
            bucket_ln = 1
            m = re.search(
                r'resource\s+"aws_s3_bucket"\s+"' + re.escape(bucket_name) + r'"',
                content
            )
            if m:
                bucket_ln = content[:m.start()].count('\n') + 1
            findings.append(Finding(
                'CRITICAL', 's3-no-public-access-block',
                f'S3 bucket has no aws_s3_bucket_public_access_block resource ({bucket_name})',
                'Create an aws_s3_bucket_public_access_block resource with all four flags = true.',
                str(path), bucket_ln,
                'GDPR Art. 32 / LGPD Art. 46'
            ))

    return findings


# ── CloudFormation parser ─────────────────────────────────────────────────────

def check_cloudformation(path: Path) -> list[Finding]:
    import yaml  # stdlib pyyaml or safe_load; fall back gracefully
    findings = []
    content = path.read_text(errors='replace')

    try:
        # Try JSON first
        try:
            template = json.loads(content)
        except json.JSONDecodeError:
            try:
                template = yaml.safe_load(content)
            except Exception:
                return []
    except Exception:
        return []

    if not isinstance(template, dict) or 'Resources' not in template:
        return []

    resources = template.get('Resources', {})
    for logical_id, resource in resources.items():
        if not isinstance(resource, dict):
            continue
        rtype = resource.get('Type', '')
        props = resource.get('Properties', {}) or {}

        # ── RDS DB Instance ──────────────────────────────────────────────────
        if rtype == 'AWS::RDS::DBInstance':
            if not props.get('StorageEncrypted', False):
                findings.append(Finding(
                    'CRITICAL', 'cfn-rds-encryption-disabled',
                    f'RDS StorageEncrypted not true ({logical_id})',
                    'Set StorageEncrypted: true',
                    str(path), 0,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))
            if props.get('PubliclyAccessible', True):
                findings.append(Finding(
                    'CRITICAL', 'cfn-rds-publicly-accessible',
                    f'RDS PubliclyAccessible is true or not set ({logical_id})',
                    'Set PubliclyAccessible: false',
                    str(path), 0,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))
            if not props.get('DeletionProtection', False):
                findings.append(Finding(
                    'MEDIUM', 'cfn-rds-no-deletion-protection',
                    f'RDS DeletionProtection not enabled ({logical_id})',
                    'Set DeletionProtection: true in production.',
                    str(path), 0,
                    'GDPR Art. 32'
                ))

        # ── S3 ───────────────────────────────────────────────────────────────
        if rtype == 'AWS::S3::Bucket':
            pub_cfg = props.get('PublicAccessBlockConfiguration', {})
            required_flags = [
                'BlockPublicAcls', 'BlockPublicPolicy',
                'IgnorePublicAcls', 'RestrictPublicBuckets'
            ]
            for flag in required_flags:
                if not pub_cfg.get(flag, False):
                    findings.append(Finding(
                        'CRITICAL', 'cfn-s3-public-access-not-blocked',
                        f'S3 {flag} not true ({logical_id})',
                        f'Set {flag}: true in PublicAccessBlockConfiguration.',
                        str(path), 0,
                        'GDPR Art. 32 / LGPD Art. 46'
                    ))
            enc = props.get('BucketEncryption', {})
            if not enc:
                findings.append(Finding(
                    'HIGH', 'cfn-s3-no-encryption',
                    f'S3 bucket has no BucketEncryption configuration ({logical_id})',
                    'Add BucketEncryption with SSE-S3 or SSE-KMS.',
                    str(path), 0,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))

        # ── CloudWatch Log Group ─────────────────────────────────────────────
        if rtype == 'AWS::Logs::LogGroup':
            ret = props.get('RetentionInDays')
            if ret is None:
                findings.append(Finding(
                    'HIGH', 'cfn-cloudwatch-no-retention',
                    f'CloudWatch log group has no RetentionInDays ({logical_id})',
                    'Set RetentionInDays. Logs retained indefinitely may violate storage limitation.',
                    str(path), 0,
                    'GDPR Art. 5(1)(e) / LGPD Art. 15'
                ))

        # ── DynamoDB ─────────────────────────────────────────────────────────
        if rtype == 'AWS::DynamoDB::Table':
            sse = props.get('SSESpecification', {})
            if not sse.get('SSEEnabled', False):
                findings.append(Finding(
                    'HIGH', 'cfn-dynamodb-encryption-disabled',
                    f'DynamoDB SSEEnabled not true ({logical_id})',
                    'Set SSESpecification.SSEEnabled: true',
                    str(path), 0,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))
            pitr = props.get('PointInTimeRecoverySpecification', {})
            if not pitr.get('PointInTimeRecoveryEnabled', False):
                findings.append(Finding(
                    'MEDIUM', 'cfn-dynamodb-no-pitr',
                    f'DynamoDB PITR not enabled ({logical_id})',
                    'Set PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled: true',
                    str(path), 0,
                    'GDPR Art. 32'
                ))

        # ── SQS ──────────────────────────────────────────────────────────────
        if rtype == 'AWS::SQS::Queue':
            if not props.get('KmsMasterKeyId') and not props.get('SqsManagedSseEnabled'):
                findings.append(Finding(
                    'HIGH', 'cfn-sqs-no-encryption',
                    f'SQS queue not encrypted ({logical_id})',
                    'Set KmsMasterKeyId or SqsManagedSseEnabled: true',
                    str(path), 0,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))

    return findings


# ── CDK TypeScript — best-effort proximity search ────────────────────────────

def check_cdk(path: Path) -> list[Finding]:
    content = path.read_text(errors='replace')
    findings = []
    lines = content.splitlines()

    def search_window(start_line: int, window: int, pattern: str) -> bool:
        end = min(start_line + window, len(lines))
        chunk = '\n'.join(lines[start_line:end])
        return bool(re.search(pattern, chunk, re.IGNORECASE))

    for i, line in enumerate(lines):
        ln = i + 1

        # RDS DatabaseInstance / DatabaseCluster
        if re.search(r'new\s+rds\.(DatabaseInstance|DatabaseCluster)\s*\(', line):
            window = '\n'.join(lines[i:min(i+30, len(lines))])
            if re.search(r'storageEncrypted\s*:\s*false', window):
                findings.append(Finding(
                    'CRITICAL', 'cdk-rds-encryption-disabled',
                    'CDK RDS storageEncrypted: false',
                    'Set storageEncrypted: true',
                    str(path), ln,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))
            if re.search(r'publiclyAccessible\s*:\s*true', window):
                findings.append(Finding(
                    'CRITICAL', 'cdk-rds-publicly-accessible',
                    'CDK RDS publiclyAccessible: true',
                    'Set publiclyAccessible: false',
                    str(path), ln,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))

        # S3 Bucket
        if re.search(r'new\s+s3\.Bucket\s*\(', line):
            window = '\n'.join(lines[i:min(i+25, len(lines))])
            if not re.search(r'blockPublicAccess\s*:', window):
                findings.append(Finding(
                    'CRITICAL', 'cdk-s3-no-block-public-access',
                    'CDK S3 Bucket missing blockPublicAccess property',
                    'Set blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL',
                    str(path), ln,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))
            elif re.search(r'blockPublicAccess\s*:(?!.*BLOCK_ALL)', window):
                findings.append(Finding(
                    'HIGH', 'cdk-s3-public-access-not-block-all',
                    'CDK S3 Bucket blockPublicAccess is not BLOCK_ALL',
                    'Use s3.BlockPublicAccess.BLOCK_ALL to prevent all public access.',
                    str(path), ln,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))
            if not re.search(r'encryption\s*:', window):
                findings.append(Finding(
                    'HIGH', 'cdk-s3-no-encryption',
                    'CDK S3 Bucket missing encryption property',
                    'Set encryption: s3.BucketEncryption.S3_MANAGED or KMS_MANAGED',
                    str(path), ln,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))

        # CloudWatch LogGroup
        if re.search(r'new\s+logs\.LogGroup\s*\(', line):
            window = '\n'.join(lines[i:min(i+20, len(lines))])
            if not re.search(r'retention\s*:', window):
                findings.append(Finding(
                    'HIGH', 'cdk-loggroup-no-retention',
                    'CDK LogGroup missing retention property',
                    'Set retention: logs.RetentionDays.THREE_MONTHS (or appropriate value)',
                    str(path), ln,
                    'GDPR Art. 5(1)(e) / LGPD Art. 15'
                ))

        # KMS Key
        if re.search(r'new\s+kms\.Key\s*\(', line):
            window = '\n'.join(lines[i:min(i+20, len(lines))])
            if re.search(r'enableKeyRotation\s*:\s*false', window):
                findings.append(Finding(
                    'HIGH', 'cdk-kms-rotation-disabled',
                    'CDK KMS Key enableKeyRotation: false',
                    'Set enableKeyRotation: true',
                    str(path), ln,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))

        # SQS Queue
        if re.search(r'new\s+sqs\.Queue\s*\(', line):
            window = '\n'.join(lines[i:min(i+20, len(lines))])
            if not re.search(r'encryption\s*:', window):
                findings.append(Finding(
                    'HIGH', 'cdk-sqs-no-encryption',
                    'CDK SQS Queue missing encryption property',
                    'Set encryption: sqs.QueueEncryption.KMS_MANAGED',
                    str(path), ln,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))
            elif re.search(r'QueueEncryption\.UNENCRYPTED', window):
                findings.append(Finding(
                    'HIGH', 'cdk-sqs-explicitly-unencrypted',
                    'CDK SQS Queue explicitly unencrypted',
                    'Change QueueEncryption.UNENCRYPTED to KMS_MANAGED or SQS_MANAGED',
                    str(path), ln,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))

        # DynamoDB Table
        if re.search(r'new\s+dynamodb\.Table\s*\(', line):
            window = '\n'.join(lines[i:min(i+25, len(lines))])
            if not re.search(r'encryption\s*:', window):
                findings.append(Finding(
                    'HIGH', 'cdk-dynamodb-no-encryption',
                    'CDK DynamoDB Table missing encryption property',
                    'Set encryption: dynamodb.TableEncryption.AWS_MANAGED (or CUSTOMER_MANAGED)',
                    str(path), ln,
                    'GDPR Art. 32 / LGPD Art. 46'
                ))
            if not re.search(r'pointInTimeRecovery\s*:', window):
                findings.append(Finding(
                    'MEDIUM', 'cdk-dynamodb-no-pitr',
                    'CDK DynamoDB Table missing pointInTimeRecovery property',
                    'Set pointInTimeRecoveryEnabled: true',
                    str(path), ln,
                    'GDPR Art. 32'
                ))

        # Cognito UserPool
        if re.search(r'new\s+cognito\.UserPool\s*\(', line):
            window = '\n'.join(lines[i:min(i+30, len(lines))])
            if not re.search(r'mfa\s*:', window):
                findings.append(Finding(
                    'MEDIUM', 'cdk-cognito-no-mfa',
                    'CDK Cognito UserPool missing mfa property',
                    'Set mfa: cognito.Mfa.REQUIRED or OPTIONAL. Default is OFF.',
                    str(path), ln,
                    'GDPR Art. 32'
                ))
            elif re.search(r'Mfa\.OFF', window):
                findings.append(Finding(
                    'MEDIUM', 'cdk-cognito-mfa-off',
                    'CDK Cognito UserPool MFA explicitly disabled',
                    'Set mfa: cognito.Mfa.OPTIONAL at minimum.',
                    str(path), ln,
                    'GDPR Art. 32'
                ))
            if not re.search(r'passwordPolicy\s*:', window):
                findings.append(Finding(
                    'MEDIUM', 'cdk-cognito-no-password-policy',
                    'CDK Cognito UserPool missing passwordPolicy',
                    'Define passwordPolicy with minLength: 12, requireSymbols: true, etc.',
                    str(path), ln,
                    'GDPR Art. 32'
                ))

    return findings


# ── CI/CD YAML checks ─────────────────────────────────────────────────────────

def check_ci_yaml(path: Path) -> list[Finding]:
    """Check GitHub Actions / GitLab CI / Bitbucket Pipelines for hardcoded secrets."""
    content = path.read_text(errors='replace')
    findings = []
    lines = content.splitlines()

    secret_patterns = [
        (r'(?i)(password|passwd|pwd|secret|api_key|access_key|private_key|token)\s*[:=]\s*["\']?[A-Za-z0-9+/=_\-]{16,}["\']?', 'Potential hardcoded secret in CI file'),
    ]
    # Exclude references that are clearly variable lookups
    safe_patterns = [
        r'\$\{\{', r'\$\{', r'\bsecrets\.', r'\benv\.', r'\bvars\.',
        r'#.*', r'your[-_]', r'<[A-Z_]+>', r'REPLACE', r'CHANGEME',
    ]

    for i, line in enumerate(lines):
        for pat, title in secret_patterns:
            if re.search(pat, line):
                if not any(re.search(sp, line) for sp in safe_patterns):
                    findings.append(Finding(
                        'CRITICAL', 'ci-hardcoded-secret',
                        title,
                        f'Line: {line.strip()[:120]}',
                        str(path), i + 1,
                        'GDPR Art. 32 / LGPD Art. 46'
                    ))

    # Check checkov and trivy are not permanently soft-failing
    if '--soft-fail' in content and 'checkov' in content:
        findings.append(Finding(
            'LOW', 'ci-checkov-soft-fail',
            'Checkov running with --soft-fail — IaC findings never block the build',
            'Consider graduated enforcement: --soft-fail for new repos, remove once baseline is clean.',
            str(path), 0,
            ''
        ))
    if 'exit-code: 0' in content and 'trivy' in content:
        findings.append(Finding(
            'LOW', 'ci-trivy-exit-zero',
            'Trivy configured with exit-code: 0 — vulnerabilities never block the build',
            'Set exit-code: 1 for CRITICAL/HIGH severity once baseline CVEs are remediated.',
            str(path), 0,
            ''
        ))

    return findings


# ── Cloud provider coverage warning ──────────────────────────────────────────

# Patterns that indicate GCP or Azure IaC resources.
# If found, we emit a warning that these are not checked.
_GCP_PATTERNS = re.compile(
    r'\bresource\s+"(google_sql_database|google_storage_bucket|google_kms|'
    r'google_container|google_bigquery|google_pubsub|google_cloud_run)\b',
    re.MULTILINE
)
_AZURE_PATTERNS = re.compile(
    r'\bresource\s+"(azurerm_sql_server|azurerm_storage_account|azurerm_key_vault|'
    r'azurerm_cosmosdb|azurerm_postgresql|azurerm_mysql|azurerm_eventhub|'
    r'azurerm_servicebus|azurerm_monitor_diagnostic)\b',
    re.MULTILINE
)
_PULUMI_PATTERNS = re.compile(r'pulumi\.yaml|@pulumi/', re.MULTILINE)


def detect_unscanned_providers(root: Path) -> list[Finding]:
    """Scan .tf and Pulumi files for non-AWS cloud resources and warn if found."""
    findings = []
    gcp_files: list[str] = []
    azure_files: list[str] = []
    pulumi_files: list[str] = []

    for path in root.rglob('*'):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        suffix = path.suffix.lower()
        if suffix not in ('.tf', '.yaml', '.yml', '.ts', '.json'):
            continue
        try:
            content = path.read_text(errors='replace')
        except Exception:
            continue
        if suffix == '.tf':
            if _GCP_PATTERNS.search(content):
                gcp_files.append(str(path))
            if _AZURE_PATTERNS.search(content):
                azure_files.append(str(path))
        if _PULUMI_PATTERNS.search(content):
            pulumi_files.append(str(path))

    if gcp_files:
        findings.append(Finding(
            'LOW', 'iac-gcp-not-scanned',
            'GCP Terraform resources detected — not covered by this scanner',
            'scan-iac.py checks AWS resource types only (aws_db_instance, aws_s3_bucket, etc.). '
            'GCP resources (google_sql_database_instance, google_storage_bucket, '
            'google_kms_crypto_key, etc.) are not evaluated. Zero AWS findings does NOT mean '
            'the GCP infrastructure is secure. Use checkov or tfsec for GCP coverage. '
            f'Files: {", ".join(gcp_files[:3])}{"..." if len(gcp_files) > 3 else ""}',
            gcp_files[0], 0,
            'GDPR Art. 32 / LGPD Art. 46'
        ))

    if azure_files:
        findings.append(Finding(
            'LOW', 'iac-azure-not-scanned',
            'Azure Terraform resources detected — not covered by this scanner',
            'scan-iac.py checks AWS resource types only. Azure resources (azurerm_sql_server, '
            'azurerm_storage_account, azurerm_key_vault, etc.) are not evaluated. '
            'Use checkov or tfsec for Azure coverage. '
            f'Files: {", ".join(azure_files[:3])}{"..." if len(azure_files) > 3 else ""}',
            azure_files[0], 0,
            'GDPR Art. 32 / LGPD Art. 46'
        ))

    if pulumi_files:
        findings.append(Finding(
            'LOW', 'iac-pulumi-not-scanned',
            'Pulumi IaC detected — not covered by this scanner',
            'scan-iac.py parses Terraform HCL and CloudFormation YAML/JSON only. '
            'Pulumi programs are not evaluated regardless of cloud provider. '
            'Use checkov or Pulumi Compliance Ready templates for Pulumi coverage. '
            f'Files: {", ".join(pulumi_files[:3])}{"..." if len(pulumi_files) > 3 else ""}',
            pulumi_files[0], 0,
            'GDPR Art. 32 / LGPD Art. 46'
        ))

    return findings


# ── file routing ──────────────────────────────────────────────────────────────

def is_cloudformation(path: Path, content: str) -> bool:
    return bool(re.search(r'AWSTemplateFormatVersion|"Resources"\s*:', content[:2000]))


def check_file(path: Path) -> list[Finding]:
    suffix = path.suffix.lower()
    name = path.name.lower()
    try:
        content = path.read_text(errors='replace')
    except Exception:
        return []

    if suffix == '.tf':
        return check_terraform(path)

    if suffix in ('.yml', '.yaml'):
        if is_cloudformation(path, content):
            return check_cloudformation(path)
        if any(x in name for x in ('workflow', 'pipeline', 'ci', 'cd', 'gitlab-ci', 'bitbucket')):
            return check_ci_yaml(path)
        if '.github' in str(path):
            return check_ci_yaml(path)
        # Try CloudFormation regardless for any YAML with Resources key
        if 'Resources:' in content:
            return check_cloudformation(path)
        return []

    if suffix == '.json' and is_cloudformation(path, content):
        return check_cloudformation(path)

    if suffix == '.ts' and ('@aws-cdk' in content or 'aws-cdk-lib' in content):
        return check_cdk(path)

    return []


# ── output ────────────────────────────────────────────────────────────────────

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

SKIP_DIRS = {
    'node_modules', '.venv', 'venv', '.git', '__pycache__',
    'dist', 'build', '.next', '.nuxt', 'vendor', 'cdk.out',
    'test', 'tests', 'spec', 'specs', '__tests__', 'fixtures',
}


def emit_text(findings: list[Finding], quiet: bool) -> None:
    if not quiet:
        print('\033[1mPrivacy IaC Scanner\033[0m')
        print('\033[0;37mScope: AWS Terraform · CloudFormation · CDK TypeScript\033[0m')
        print('\033[0;37mNote:  GCP, Azure, and Pulumi are NOT checked — see LOW findings if detected.\033[0m')
        print('──────────────────────────────────────────────────────')

    colors = {'CRITICAL': '\033[0;31m', 'HIGH': '\033[1;33m',
               'MEDIUM': '\033[0;36m', 'LOW': '\033[0;37m'}
    reset = '\033[0m'
    bold = '\033[1m'

    for f in findings:
        color = colors.get(f.severity, '')
        print(f"{color}[{f.severity}]{reset} {bold}{f.title}{reset}")
        if f.file:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            print(f"  {loc}")
        if f.detail:
            print(f"  {f.detail}")
        if f.regulation:
            print(f"  Regulation: {f.regulation}")
        print()

    print('──────────────────────────────────────────────────────')
    if not findings:
        print('\033[0;32m✓ No IaC privacy/security findings.\033[0m')
    else:
        by_sev = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        parts = [f"{by_sev.get(s, 0)} {s}" for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] if by_sev.get(s)]
        print(f"\033[0;31m✗ {len(findings)} finding(s): {', '.join(parts)}\033[0m")


def emit_json(findings: list[Finding]) -> None:
    out = [
        {
            'severity': f.severity,
            'rule_id': f.rule_id,
            'title': f.title,
            'detail': f.detail,
            'file': f.file,
            'line': f.line,
            'regulation': f.regulation,
        }
        for f in findings
    ]
    print(json.dumps(out, indent=2))


def emit_sarif(findings: list[Finding]) -> None:
    results = []
    rules = {}
    for f in findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                'id': f.rule_id,
                'name': f.rule_id.replace('-', '_'),
                'shortDescription': {'text': f.title},
                'defaultConfiguration': {
                    'level': 'error' if f.severity == 'CRITICAL' else
                             'warning' if f.severity == 'HIGH' else 'note'
                },
            }
        results.append({
            'ruleId': f.rule_id,
            'level': 'error' if f.severity == 'CRITICAL' else
                     'warning' if f.severity == 'HIGH' else 'note',
            'message': {'text': f'{f.title}. {f.detail}'.strip('. ')},
            'locations': [{'physicalLocation': {
                'artifactLocation': {'uri': f.file, 'uriBaseId': '%SRCROOT%'},
                'region': {'startLine': max(f.line, 1)},
            }}],
        })
    sarif = {
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{'tool': {'driver': {
            'name': 'scan-iac',
            'version': '1.0.0',
            'rules': list(rules.values()),
        }}, 'results': results}],
    }
    print(json.dumps(sarif, indent=2))


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('directory', nargs='?', default='.', help='Root directory to scan')
    parser.add_argument('--dir', '-d', dest='directory')
    parser.add_argument('--format', '-f', choices=['text', 'json', 'sarif'], default='text')
    parser.add_argument('--quiet', '-q', action='store_true')
    args = parser.parse_args()

    root = Path(args.directory or '.')
    if not root.is_dir():
        print(f"Error: '{root}' is not a directory", file=sys.stderr)
        sys.exit(2)

    all_findings: list[Finding] = []

    for path in root.rglob('*'):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        findings = check_file(path)
        all_findings.extend(findings)

    # Warn if GCP, Azure, or Pulumi IaC is present — those providers are not checked.
    all_findings.extend(detect_unscanned_providers(root))

    all_findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line))

    if args.format == 'text':
        emit_text(all_findings, args.quiet)
    elif args.format == 'json':
        emit_json(all_findings)
    elif args.format == 'sarif':
        emit_sarif(all_findings)

    sys.exit(1 if all_findings else 0)


if __name__ == '__main__':
    main()
