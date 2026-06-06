#!/usr/bin/env bash
# scan-soft-deletes.sh — detect soft-delete patterns without companion anonymization,
# orphaned FK references, ORM cascade bypass risk, event sourcing without crypto
# shredding, and data warehouse integrations without deletion propagation.
#
# These are the deletion-layer checks that a privacy audit must verify deterministically,
# not by asking an LLM to interpret grep output. Each check produces a structured finding
# with severity, location, and the specific regulation violated.
#
# Usage:
#   ./scripts/scan-soft-deletes.sh [options] [directory]
#
# Options:
#   -d, --dir DIR        Directory to scan (default: current directory)
#   -f, --format FORMAT  Output format: text (default), json
#   -q, --quiet          Only print findings, no header
#   -h, --help           Show this help
#
# Exit codes:
#   0  No findings
#   1  Findings detected
#   2  Script error

set -euo pipefail

SCAN_DIR="."
FORMAT="text"
QUIET=false
FOUND=0

if [ -t 1 ]; then
  RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; RESET=''
fi

while [[ $# -gt 0 ]]; do
  case $1 in
    -d|--dir)    SCAN_DIR="$2"; shift 2 ;;
    -f|--format) FORMAT="$2"; shift 2 ;;
    -q|--quiet)  QUIET=true; shift ;;
    -h|--help)
      sed -n '/^# Usage:/,/^[^#]/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) SCAN_DIR="$1"; shift ;;
  esac
done

if [ ! -d "$SCAN_DIR" ]; then
  echo "Error: directory '$SCAN_DIR' not found" >&2
  exit 2
fi

# ── shared grep flags ─────────────────────────────────────────────────────────
EXCLUDE_DIRS=(
  --exclude-dir=node_modules --exclude-dir=.venv --exclude-dir=venv
  --exclude-dir=.git --exclude-dir=__pycache__ --exclude-dir=vendor
  --exclude-dir=dist --exclude-dir=build --exclude-dir=.next
  --exclude-dir=test --exclude-dir=tests --exclude-dir=spec
  --exclude-dir=specs --exclude-dir=__tests__ --exclude-dir=fixtures
)
EXCLUDE_TEST_FILES=(
  --exclude='*.test.py' --exclude='*.spec.py'
  --exclude='*.test.ts' --exclude='*.spec.ts'
  --exclude='*.test.js' --exclude='*.spec.js'
  --exclude='*_test.go' --exclude='*_spec.rb'
)

# ── JSON accumulator ──────────────────────────────────────────────────────────
JSON_FINDINGS="[]"

emit_finding() {
  local severity="$1" rule="$2" title="$3" detail="$4" location="$5" regulation="$6"
  FOUND=1

  if [ "$FORMAT" = "text" ]; then
    local color="$RED"
    [ "$severity" = "HIGH" ]   && color="$YELLOW"
    [ "$severity" = "MEDIUM" ] && color="$CYAN"
    [ "$severity" = "LOW" ]    && color="$CYAN"
    echo -e "${color}[${severity}]${RESET} ${BOLD}${title}${RESET}"
    [ -n "$location" ]   && echo -e "  ${location}"
    [ -n "$detail" ]     && echo -e "  ${detail}"
    [ -n "$regulation" ] && echo -e "  Regulation: ${regulation}"
    echo ""
  else
    local escaped_title escaped_detail escaped_loc
    escaped_title=$(echo "$title"  | sed 's/"/\\"/g' | tr -d '\n')
    escaped_detail=$(echo "$detail" | sed 's/"/\\"/g' | tr -d '\n')
    escaped_loc=$(echo "$location"  | sed 's/"/\\"/g' | tr -d '\n')
    JSON_FINDINGS=$(python3 -c "
import json, sys
findings = json.loads(sys.stdin.read())
findings.append({
  'severity': '$severity', 'rule': '$rule',
  'title': '$escaped_title', 'detail': '$escaped_detail',
  'location': '$escaped_loc', 'regulation': '$regulation'
})
print(json.dumps(findings, indent=2))
" <<< "$JSON_FINDINGS")
  fi
}

# ── header ────────────────────────────────────────────────────────────────────
if [ "$QUIET" = false ] && [ "$FORMAT" = "text" ]; then
  echo -e "${BOLD}Soft-Delete & Deletion Coverage Scanner${RESET}"
  echo -e "Scanning: ${CYAN}${SCAN_DIR}${RESET}"
  echo "──────────────────────────────────────────────────────"
  echo ""
fi

# ─────────────────────────────────────────────────────────────────────────────
# CHECK A — Soft delete without companion anonymization (HIGH)
#
# A bare soft-delete flag (deleted_at, is_deleted, archived_at) is not erasure
# under GDPR Art. 17 / LGPD Art. 18(VI). It is concealment (ocultação).
# A companion anonymization query or scheduled purge job is required.
# ─────────────────────────────────────────────────────────────────────────────

SOFT_DELETE_FILES=$(grep -rPln \
  "${EXCLUDE_DIRS[@]}" "${EXCLUDE_TEST_FILES[@]}" \
  --include="*.py" --include="*.rb" --include="*.ts" --include="*.js" \
  --include="*.go" --include="*.java" --include="*.sql" \
  '\bdeleted_at\b|\bis_deleted\b|\barchived_at\b|\bsoft.delet|\bdeletedAt\b' \
  "$SCAN_DIR" 2>/dev/null || true)

ANONYMIZATION_EXISTS=false
ANONYMIZATION_FILES=$(grep -rPln \
  "${EXCLUDE_DIRS[@]}" \
  --include="*.py" --include="*.rb" --include="*.ts" --include="*.js" \
  --include="*.go" --include="*.java" --include="*.sql" \
  'anonymi[sz]|redacted\.invalid|@deleted\b|deleted_\d+@|nulled|NULL.*email|email.*NULL|scheduled_for_deletion|deletion_scheduled' \
  "$SCAN_DIR" 2>/dev/null || true)

if [ -n "$ANONYMIZATION_FILES" ]; then
  ANONYMIZATION_EXISTS=true
fi

if [ -n "$SOFT_DELETE_FILES" ]; then
  if $ANONYMIZATION_EXISTS; then
    # Both exist — flag for manual confirmation they're actually connected
    while IFS= read -r file; do
      [ -z "$file" ] && continue
      emit_finding "LOW" "soft-delete-verify-anonymization" \
        "Soft-delete pattern found — verify anonymization is connected" \
        "File uses soft-delete. Anonymization patterns also exist in the codebase, but confirm they cover this table and are actually invoked on deletion." \
        "$file" \
        "GDPR Art. 17 / LGPD Art. 18(VI)"
    done <<< "$SOFT_DELETE_FILES"
  else
    # Soft delete found, no anonymization anywhere — definite HIGH gap
    while IFS= read -r file; do
      [ -z "$file" ] && continue
      emit_finding "HIGH" "soft-delete-without-anonymization" \
        "Soft-delete flag found with no companion anonymization in codebase" \
        "deleted_at / is_deleted / archived_at flags are concealment, not erasure. Add an anonymization query (email → deleted+ID@deleted.invalid, name → 'DELETED', phone → NULL) and a deletion_registry entry." \
        "$file" \
        "GDPR Art. 17 / LGPD Art. 18(VI)"
    done <<< "$SOFT_DELETE_FILES"
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# CHECK B — Orphaned user references without FK constraint (MEDIUM)
#
# user_id / owner_id columns with no REFERENCES constraint accumulate orphan
# PII silently after user deletion. The DB does not enforce cleanup.
#
# Scope: schema/model definition files only. user_id in an API handler,
# service layer, serializer, or DTO is not an orphan risk — the FK lives in
# the model file. Scanning application logic produces noise that trains
# engineers to ignore this check. Each language uses a content filter to
# confirm the file is a schema definition before flagging it.
# ─────────────────────────────────────────────────────────────────────────────

FK_PATTERN='\buser_id\b|\bowner_id\b|\bauthor_id\b|\bcreated_by\b|\bupdated_by\b'
CANDIDATE_FILES=""

# SQL: all SQL files are DDL/DML — inherently schema scope
_sql=$(grep -rPln "${EXCLUDE_DIRS[@]}" "${EXCLUDE_TEST_FILES[@]}" \
  --include="*.sql" "$FK_PATTERN" "$SCAN_DIR" 2>/dev/null || true)
CANDIDATE_FILES="${CANDIDATE_FILES}"$'\n'"${_sql}"

# Python: only files that also contain ORM column/model markers
while IFS= read -r f; do
  [ -z "$f" ] && continue
  if grep -qP 'Column\s*\(|mapped_column\s*\(|models\.Model\b|DeclarativeBase|declarative_base\s*\(' "$f" 2>/dev/null; then
    CANDIDATE_FILES="${CANDIDATE_FILES}"$'\n'"$f"
  fi
done < <(grep -rPln "${EXCLUDE_DIRS[@]}" "${EXCLUDE_TEST_FILES[@]}" \
  --include="*.py" "$FK_PATTERN" "$SCAN_DIR" 2>/dev/null || true)

# Ruby: migration files (path contains /migrate/) or schema.rb, or
#        files that contain create_table / add_column (ActiveRecord DSL)
while IFS= read -r f; do
  [ -z "$f" ] && continue
  if echo "$f" | grep -qP '/migrate/|schema\.rb$'; then
    CANDIDATE_FILES="${CANDIDATE_FILES}"$'\n'"$f"
  elif grep -qP 'create_table|add_column' "$f" 2>/dev/null; then
    CANDIDATE_FILES="${CANDIDATE_FILES}"$'\n'"$f"
  fi
done < <(grep -rPln "${EXCLUDE_DIRS[@]}" "${EXCLUDE_TEST_FILES[@]}" \
  --include="*.rb" "$FK_PATTERN" "$SCAN_DIR" 2>/dev/null || true)

# Prisma: all .prisma files are schema by definition
_prisma=$(grep -rPln "${EXCLUDE_DIRS[@]}" \
  --include="*.prisma" \
  '\buser_id\b|\buserId\b|\bowner_id\b|\bownerId\b|\bauthorId\b|\bcreatedById\b|\bupdatedById\b' \
  "$SCAN_DIR" 2>/dev/null || true)
CANDIDATE_FILES="${CANDIDATE_FILES}"$'\n'"${_prisma}"

# TypeScript: only files with ORM entity decorators (@Entity, @Column, @ManyToOne)
while IFS= read -r f; do
  [ -z "$f" ] && continue
  if grep -qP '@Entity\b|@Column\b|@ManyToOne\b|@OneToMany\b|@JoinColumn\b' "$f" 2>/dev/null; then
    CANDIDATE_FILES="${CANDIDATE_FILES}"$'\n'"$f"
  fi
done < <(grep -rPln "${EXCLUDE_DIRS[@]}" "${EXCLUDE_TEST_FILES[@]}" \
  --include="*.ts" \
  '\buser_id\b|\buserId\b|\bownerId\b|\bauthorId\b|\bcreatedById\b' \
  "$SCAN_DIR" 2>/dev/null || true)

# Deduplicate and strip blanks
CANDIDATE_FILES=$(echo "$CANDIDATE_FILES" | grep -v '^$' | sort -u || true)

# For each candidate schema file, check whether an FK declaration exists
if [ -n "$CANDIDATE_FILES" ]; then
  while IFS= read -r file; do
    [ -z "$file" ] && continue
    suffix="${file##*.}"

    has_fk=false
    case "$suffix" in
      sql)
        if grep -qiP 'REFERENCES\s+(users|"users"|`users`)' "$file" 2>/dev/null; then
          has_fk=true
        fi
        ;;
      py)
        if grep -qP 'ForeignKey\s*\(|models\.ForeignKey|relationship\s*\(' "$file" 2>/dev/null; then
          has_fk=true
        fi
        ;;
      rb)
        if grep -qP 'belongs_to\s+:user|add_foreign_key' "$file" 2>/dev/null; then
          has_fk=true
        fi
        ;;
      prisma)
        if grep -qP '@relation\s*\(|references:\s*\[' "$file" 2>/dev/null; then
          has_fk=true
        fi
        ;;
      ts)
        if grep -qP '@ManyToOne\b|@JoinColumn\b|@RelationId\b' "$file" 2>/dev/null; then
          has_fk=true
        fi
        ;;
    esac

    if ! $has_fk; then
      matching_lines=$(grep -nP '\buser_id\b|\buserId\b|\bowner_id\b|\bauthorId\b|\bcreated_by\b' \
        "$file" 2>/dev/null | head -5 || true)
      emit_finding "MEDIUM" "orphaned-user-ref-no-fk" \
        "Schema file has user_id / owner_id column with no FK constraint" \
        "Without REFERENCES users(id) ON DELETE CASCADE/SET NULL, these rows accumulate orphan PII after user deletion. Add a DB-level FK constraint. Matching lines: $(echo "$matching_lines" | tr '\n' ' ' | cut -c1-200)" \
        "$file" \
        "GDPR Art. 17 / LGPD Art. 18(VI)"
    fi
  done <<< "$CANDIDATE_FILES"
fi

# ─────────────────────────────────────────────────────────────────────────────
# CHECK C — ORM-only cascade without DB-level FK (MEDIUM)
#
# Django on_delete and Rails dependent: operate at the application layer.
# Any service or script that accesses the DB directly bypasses this logic.
# The fix is a DB-level ON DELETE CASCADE / SET NULL constraint.
# ─────────────────────────────────────────────────────────────────────────────

# Django: flag DO_NOTHING (no cascade at all) as HIGH; others as MEDIUM
DJANGO_DO_NOTHING=$(grep -rPn \
  "${EXCLUDE_DIRS[@]}" "${EXCLUDE_TEST_FILES[@]}" \
  --include="*.py" \
  'on_delete\s*=\s*models\.DO_NOTHING' \
  "$SCAN_DIR" 2>/dev/null || true)

if [ -n "$DJANGO_DO_NOTHING" ]; then
  while IFS= read -r match; do
    [ -z "$match" ] && continue
    file=$(echo "$match" | cut -d: -f1)
    lineno=$(echo "$match" | cut -d: -f2)
    emit_finding "HIGH" "django-on-delete-do-nothing" \
      "Django ForeignKey with on_delete=DO_NOTHING — no cascade at all" \
      "on_delete=models.DO_NOTHING means user deletion leaves orphan rows with PII indefinitely. Change to CASCADE or SET_NULL and add a matching DB-level FK constraint." \
      "${file}:${lineno}" \
      "GDPR Art. 17 / LGPD Art. 18(VI)"
  done <<< "$DJANGO_DO_NOTHING"
fi

# Django CASCADE/SET_NULL/PROTECT — app-layer only, flag if no DB FK found
DJANGO_CASCADE=$(grep -rPln \
  "${EXCLUDE_DIRS[@]}" "${EXCLUDE_TEST_FILES[@]}" \
  --include="*.py" \
  'on_delete\s*=\s*models\.(CASCADE|SET_NULL|PROTECT)' \
  "$SCAN_DIR" 2>/dev/null || true)

if [ -n "$DJANGO_CASCADE" ]; then
  # Check whether any DB-level migration adds FK constraints
  DB_FK_EXISTS=$(grep -rPl \
    "${EXCLUDE_DIRS[@]}" \
    --include="*.sql" --include="*.py" \
    'ON DELETE (CASCADE|SET NULL)|ADD CONSTRAINT.*FOREIGN KEY|AddForeignKey' \
    "$SCAN_DIR" 2>/dev/null || true)

  if [ -z "$DB_FK_EXISTS" ]; then
    emit_finding "MEDIUM" "orm-cascade-no-db-fk" \
      "Django on_delete cascade found but no DB-level FK constraints detected" \
      "Django's on_delete is enforced only via the ORM. Services, scripts, or pipelines that access the DB directly bypass it. Add ON DELETE CASCADE / SET NULL constraints at the DB level." \
      "$(echo "$DJANGO_CASCADE" | head -3 | tr '\n' ' ')" \
      "GDPR Art. 17 / LGPD Art. 18(VI)"
  fi
fi

# Rails: dependent: :delete_all skips callbacks and may leave child records' children orphaned
RAILS_DELETE_ALL=$(grep -rPn \
  "${EXCLUDE_DIRS[@]}" "${EXCLUDE_TEST_FILES[@]}" \
  --include="*.rb" \
  'dependent:\s*:delete_all' \
  "$SCAN_DIR" 2>/dev/null || true)

if [ -n "$RAILS_DELETE_ALL" ]; then
  while IFS= read -r match; do
    [ -z "$match" ] && continue
    file=$(echo "$match" | cut -d: -f1)
    lineno=$(echo "$match" | cut -d: -f2)
    emit_finding "MEDIUM" "rails-dependent-delete-all" \
      "Rails dependent: :delete_all skips callbacks and nested cascades" \
      "delete_all issues a single SQL DELETE without running callbacks or dependent: chains on children of children. Use dependent: :destroy unless performance is critical, and add a DB-level FK." \
      "${file}:${lineno}" \
      "GDPR Art. 17 / LGPD Art. 18(VI)"
  done <<< "$RAILS_DELETE_ALL"
fi

# ─────────────────────────────────────────────────────────────────────────────
# CHECK D — Event sourcing / append-only logs without crypto shredding (HIGH)
#
# Kafka, Kinesis, DynamoDB Streams, or any append-only event log is
# architecturally incompatible with deletion. The only compliant strategy
# is crypto shredding: encrypt PII fields per-user with a KMS-derived key;
# "deletion" = schedule that key for destruction.
# ─────────────────────────────────────────────────────────────────────────────

EVENT_SOURCING_FILES=$(grep -rPln \
  "${EXCLUDE_DIRS[@]}" \
  --include="*.py" --include="*.ts" --include="*.js" \
  --include="*.go" --include="*.java" \
  'KafkaProducer|KinesisClient|DynamoDBStreams|EventStore|event_store|append_event|EventBus\b|outbox\b' \
  "$SCAN_DIR" 2>/dev/null || true)

if [ -n "$EVENT_SOURCING_FILES" ]; then
  CRYPTO_SHRED_EXISTS=$(grep -rPl \
    "${EXCLUDE_DIRS[@]}" \
    --include="*.py" --include="*.ts" --include="*.js" --include="*.go" \
    'crypto.?shred|shred_key|destroy.*key|ScheduleKeyDeletion|schedule_key_deletion|kms.*delete.*key|KMSClient.*delete' \
    "$SCAN_DIR" 2>/dev/null || true)

  if [ -z "$CRYPTO_SHRED_EXISTS" ]; then
    emit_finding "HIGH" "event-sourcing-no-crypto-shredding" \
      "Event sourcing / append-only log detected with no crypto shredding implementation" \
      "Kafka/Kinesis/event store records cannot be deleted. Implement crypto shredding: encrypt PII fields with a per-user KMS key; on erasure request, call ScheduleKeyDeletion. See cookbook/right-to-erasure.md." \
      "$(echo "$EVENT_SOURCING_FILES" | head -3 | tr '\n' ' ')" \
      "GDPR Art. 17 / LGPD Art. 18(VI)"
  else
    emit_finding "LOW" "event-sourcing-verify-crypto-shredding" \
      "Event sourcing detected — verify crypto shredding covers all PII fields" \
      "Crypto shredding patterns found, but confirm every PII field written to the event log is encrypted under a per-user key. Check that ScheduleKeyDeletion is called as part of the erasure flow." \
      "$(echo "$EVENT_SOURCING_FILES" | head -3 | tr '\n' ' ')" \
      "GDPR Art. 17 / LGPD Art. 18(VI)"
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# CHECK E — Data warehouse / analytics pipeline without deletion propagation (HIGH)
#
# BigQuery, Redshift, Snowflake, and dbt pipelines do not automatically
# receive deletions from the production database. A deletion in the main DB
# leaves the data intact in the warehouse unless the pipeline was explicitly
# designed to propagate it.
# ─────────────────────────────────────────────────────────────────────────────

WAREHOUSE_FILES=$(grep -rPln \
  "${EXCLUDE_DIRS[@]}" \
  --include="*.py" --include="*.ts" --include="*.yml" --include="*.yaml" \
  --include="*.sql" --include="*.json" \
  'bigquery|redshift|snowflake|dbt\b|fivetran|airbyte|stitch\b|meltano|databricks' \
  "$SCAN_DIR" 2>/dev/null || true)

if [ -n "$WAREHOUSE_FILES" ]; then
  DELETION_PROPAGATION=$(grep -rPl \
    "${EXCLUDE_DIRS[@]}" \
    --include="*.py" --include="*.ts" --include="*.sql" \
    'delete.*warehouse|warehouse.*delete|gdpr.*sync|erasure.*warehouse|deletion.*propagat|deletion_registry|exclude_deleted|soft_delete.*filter' \
    "$SCAN_DIR" 2>/dev/null || true)

  if [ -z "$DELETION_PROPAGATION" ]; then
    emit_finding "HIGH" "warehouse-no-deletion-propagation" \
      "Data warehouse integration found with no deletion propagation path" \
      "BigQuery / Redshift / Snowflake / dbt does not automatically receive production DB deletions. Add a warehouse deletion step to the erasure flow, or a deletion_registry-based dbt exclusion macro. See cookbook/right-to-erasure.md." \
      "$(echo "$WAREHOUSE_FILES" | head -3 | tr '\n' ' ')" \
      "GDPR Art. 17 / LGPD Art. 18(VI)"
  else
    emit_finding "LOW" "warehouse-verify-deletion-propagation" \
      "Data warehouse detected — verify deletion propagation is complete" \
      "Deletion propagation patterns found. Confirm the pipeline covers ALL tables with PII, runs after every erasure request, and is tested end-to-end." \
      "$(echo "$WAREHOUSE_FILES" | head -3 | tr '\n' ' ')" \
      "GDPR Art. 17 / LGPD Art. 18(VI)"
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# CHECK F — deletion_registry absent (MEDIUM)
#
# Without a deletion_registry, restoring a backup re-introduces deleted user
# data. The registry is how the erasure flow survives a DB restore.
# ─────────────────────────────────────────────────────────────────────────────

DELETION_REGISTRY=$(grep -rPl \
  "${EXCLUDE_DIRS[@]}" \
  --include="*.py" --include="*.ts" --include="*.sql" --include="*.rb" \
  'deletion_registry|erasure_registry|DeletionRecord|deletion_log' \
  "$SCAN_DIR" 2>/dev/null || true)

if [ -z "$DELETION_REGISTRY" ]; then
  # Only flag if there is deletion-related code (avoid false positives on brand-new repos)
  HAS_DELETE_CODE=$(grep -rPl \
    "${EXCLUDE_DIRS[@]}" "${EXCLUDE_TEST_FILES[@]}" \
    --include="*.py" --include="*.ts" --include="*.rb" \
    'delete.*account|erasure|right.*forget|gdpr.*delete|dsar' \
    "$SCAN_DIR" 2>/dev/null || true)

  if [ -n "$HAS_DELETE_CODE" ]; then
    emit_finding "MEDIUM" "no-deletion-registry" \
      "Deletion-related code found but no deletion_registry table/model" \
      "Without a deletion_registry (user_id_hash, deleted_at), a DB restore will re-introduce PII for deleted users. Add a deletion_registry table and write to it in the erasure flow. See cookbook/right-to-erasure.md." \
      "" \
      "GDPR Art. 17 / LGPD Art. 18(VI)"
  fi
fi

# ── output ────────────────────────────────────────────────────────────────────
if [ "$FORMAT" = "json" ]; then
  echo "$JSON_FINDINGS"
elif [ "$FORMAT" = "text" ]; then
  echo "──────────────────────────────────────────────────────"
  if [ "$FOUND" -eq 0 ]; then
    echo -e "${GREEN}✓ No deletion-layer gaps detected.${RESET}"
  else
    echo -e "${RED}✗ Findings detected — see above. These represent GDPR Art. 17 / LGPD Art. 18(VI) gaps.${RESET}"
    echo ""
    echo "Remediation references:"
    echo "  cookbook/right-to-erasure.md      — deletion patterns and registry"
    echo "  cookbook/anonymization-vs-pseudonymization.md — choosing the right technique"
  fi
fi

exit $FOUND
