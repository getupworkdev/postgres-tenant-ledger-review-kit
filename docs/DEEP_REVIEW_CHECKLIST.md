# Deep review checklist

## Before the first production migration

**Roles and grants**
- [ ] `audit/audit.sql` on staging: no high findings; every medium has a written reason.
- [ ] Every exposed table: `REVOKE ALL` from `anon`/`authenticated` first, then the exact grants the policies assume.
- [ ] Every `SECURITY DEFINER` function: `SET search_path = ''`, fully qualified names, `REVOKE ... FROM PUBLIC`, its own `auth.uid()` and tenant check.
- [ ] Default privileges reviewed for the roles that run migrations, not only `postgres`.
- [ ] `service_role` key used only server-side; never in a client bundle or a public env var.

**Tenant isolation**
- [ ] Tenant id derived from membership (or a verified JWT claim), never from a request argument alone.
- [ ] Policies call helper functions as `(select fn())` so they are evaluated once per query, not per row.
- [ ] Indexes on `tenant_id` (and on the membership lookup) so RLS does not turn into sequential scans.
- [ ] A test that logs in as tenant B and tries to read, write and call every RPC for tenant A.

**Migrations**
- [ ] Each migration runs cleanly on a copy of production data volume, with timings.
- [ ] Long locks avoided: `CREATE INDEX CONCURRENTLY`, constraints added `NOT VALID` then validated.
- [ ] Rollback or forward-fix plan written down for each one.

**Connections**
- [ ] Pooler mode known (transaction vs session). In transaction mode, no `SET` outside a transaction, no session advisory locks, no prepared statements unless supported.
- [ ] Auth hooks tested for latency and failure behaviour.

## Before the Shopify inventory push goes live

- [ ] HMAC verified over the raw body bytes, constant-time compare, before any parsing.
- [ ] `X-Shopify-Webhook-Id` stored as the idempotency key; a replay posts nothing.
- [ ] Out-of-order deliveries give the same final level (deltas, not overwrites).
- [ ] Absolute levels from Shopify converted to deltas against the ledger, inside one transaction with the cache update.
- [ ] Rebuild-from-log tested under concurrent webhook load (advisory lock per tenant).
- [ ] Drift check scheduled and alerting; a non-empty drift view pages someone.
- [ ] Outbound pushes to Shopify are rate-limited, retried with backoff, and idempotent on our side.
- [ ] Reconciliation job compares Shopify's levels with the ledger and posts correcting events, never edits.
