#!/usr/bin/env bash
# Runs every test against a throwaway Postgres.
# Usage: PGHOST=... PGPORT=... PGUSER=postgres tests/run.sh
set -euo pipefail
cd "$(dirname "$0")/.."

psql_db() { psql -X -q -v ON_ERROR_STOP=1 -d "$1" "${@:2}"; }

for db in kit_demo kit_broken; do
  psql -X -q -d postgres -c "drop database if exists $db" -c "create database $db"
  psql_db "$db" -f stub/00_supabase_stub.sql
done

echo "== grant semantics"
psql_db kit_demo -f tests/00_grant_semantics.sql

echo "== demo schema: ledger and tenant isolation"
psql_db kit_demo -f demo/10_inventory_ledger.sql
psql_db kit_demo -f tests/10_ledger_isolation.sql

echo "== audit: demo schema should be clean"
findings=$(psql_db kit_demo -At -F '|' -v schemas=public -f audit/audit.sql | grep -E '^(high|medium)\|' || true)
if [[ -n "$findings" ]]; then
  echo "unexpected findings on the demo schema:"; echo "$findings"; exit 1
fi
echo "ok  no high or medium findings"

echo "== audit: broken schema should be caught"
psql_db kit_broken -f broken/10_common_mistakes.sql
out=$(psql_db kit_broken -At -F '|' -v schemas=public -f audit/audit.sql)
expect() {
  if grep -qE "^$1\|$2\|$3" <<<"$out"; then echo "ok  $2 $3"; else echo "MISSING: $1 $2 $3"; echo "$out"; exit 1; fi
}
expect high   rls_disabled            'public\.orders'
expect high   policy_always_true      'public\.customers policy customers_all'
expect medium client_write_grant      'public\.invoices'
expect high   definer_no_search_path  'public\.invoice_total'
expect medium definer_exposed_rpc     'public\.invoice_total'
expect high   view_bypasses_rls       'public\.customer_emails'
expect high   ledger_mutable          'public\.payment_ledger'
expect info   default_privileges      'public / tables'

echo
echo "full report on the broken schema:"
psql_db kit_broken -v schemas=public -f audit/audit.sql
echo "all tests passed"
