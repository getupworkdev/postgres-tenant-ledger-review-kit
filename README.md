# postgres-tenant-ledger-review-kit

Read-only security review for Postgres and Supabase, plus a reference
multi-tenant inventory ledger that passes it.

Most data exposure in Supabase projects is not exotic. A table without RLS, a
policy that says `true`, a `SECURITY DEFINER` function anyone can call, a view
that quietly runs as its owner, or a `GRANT SELECT` that someone thought would
narrow an earlier `GRANT ALL`. This kit finds those with one read-only query
and shows what the correct version looks like, with tests.

## What is in it

| Path | What it does |
|---|---|
| `audit/audit.sql` | One read-only query (inside `BEGIN READ ONLY ... ROLLBACK`). Lists findings by severity for the schemas you expose. Safe on staging with a read-only role. |
| `demo/10_inventory_ledger.sql` | Multi-tenant inventory: append-only `inventory_events`, derived `inventory_levels` cache, one `SECURITY DEFINER` write path that checks membership, rebuild-from-log, drift view. |
| `broken/10_common_mistakes.sql` | Six real-world mistakes, used to prove the audit catches each one. |
| `stub/00_supabase_stub.sql` | `anon`, `authenticated`, `service_role`, `auth.uid()` and Supabase's default grants, so everything runs on plain Postgres in CI. |
| `tests/` | Grant semantics, tenant isolation, ledger behaviour, and audit results on both schemas. |
| `webhooks/shopify.mjs` | Shopify HMAC check over the raw body and mapping of a delivery to an idempotent ledger event. |
| `docs/` | Deep-review checklist and a weekly findings note template. |

## What the audit checks

| Check | Severity | Why it matters |
|---|---|---|
| `rls_disabled` | high | Table reachable by `anon`/`authenticated` with RLS off. With Supabase defaults that is read and write for anyone with the anon key. |
| `policy_always_true` | high | Permissive write policy with `using (true)` or `with check (true)`. |
| `select_policy_always_true` | medium | Every row readable. Fine for genuinely public data, a leak for tenant data. |
| `client_write_grant` | medium | Client roles hold INSERT/UPDATE/DELETE/TRUNCATE. RLS still applies, but one bad policy becomes a write hole. |
| `definer_no_search_path` | high | `SECURITY DEFINER` without `SET search_path`. Unqualified names can be shadowed. |
| `definer_exposed_rpc` | medium | `SECURITY DEFINER` callable from an exposed schema, so it is an RPC running with the owner's rights. Each needs its own `auth.uid()` and tenant check. Mark reviewed ones with `audit: reviewed` in the function comment. |
| `view_bypasses_rls` | high | View over an RLS table without `security_invoker`, selectable by clients. |
| `ledger_mutable` | high | Table commented `append-only` that can still be updated, deleted or truncated. |
| `default_privileges` | info | What future objects will be granted automatically. |

```bash
psql "$STAGING_URL" -v schemas='public,api' -f audit/audit.sql
```

## The grant question

Privileges in Postgres are a set, and `GRANT` only adds to it. After
`GRANT ALL`, a later `GRANT SELECT` changes nothing: INSERT, UPDATE and DELETE
are still there until you `REVOKE` them. Supabase grants ALL on new `public`
tables to `anon` and `authenticated`, so in practice RLS is often the only
thing protecting the data. Functions have the same trap: EXECUTE is granted
to `PUBLIC` by default, so revoking it from `authenticated` alone leaves it
callable. `tests/00_grant_semantics.sql` demonstrates both.

## The ledger design

- **The log is the truth.** `inventory_events` is insert-only. No client role
  has UPDATE or DELETE, and a trigger blocks UPDATE, DELETE and TRUNCATE even
  for the owner. Corrections are new events.
- **Retries are harmless.** `(tenant_id, source, source_event_id)` is unique,
  so a webhook delivered twice posts once.
- **Order does not matter.** The cache is a sum of deltas, so out-of-order
  delivery gives the same result.
- **The cache can be thrown away.** `private.rebuild_inventory_levels()`
  recomputes it from the log under an advisory lock, and
  `private.inventory_drift` shows any row where cache and log disagree.
- **Tenant isolation lives in the database.** Reads go through RLS using
  `private.is_member()`. The only write path is `record_inventory_event()`,
  which takes the tenant from the caller's membership check rather than
  trusting the argument alone. `private` is not an exposed schema, so the
  helpers are not RPCs.

## Run the tests

Needs a throwaway Postgres 15+ and Node 20+.

```bash
PGHOST=localhost PGUSER=postgres tests/run.sh   # SQL: grants, isolation, ledger, audit
node --test webhooks/shopify.test.mjs           # HMAC and event mapping
```

Expected: every isolation and ledger check passes, the audit reports no high
or medium findings on the demo schema, and it reports all six planted mistakes
on the broken one.

## License

MIT
