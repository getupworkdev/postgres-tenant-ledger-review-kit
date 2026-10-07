-- Deliberately wrong. Each block is a mistake that shows up in real Supabase
-- projects. The audit must report every one of them; tests/20_audit.sql checks that.

-- 1. RLS never enabled. With Supabase's default grants, anon can read and write it.
create table public.orders (
  id        bigint generated always as identity primary key,
  tenant_id uuid not null,
  total     numeric not null
);

-- 2. RLS on, but a policy that lets everyone through.
create table public.customers (
  id        bigint generated always as identity primary key,
  tenant_id uuid not null,
  email     text not null
);
alter table public.customers enable row level security;
create policy customers_all on public.customers for all using (true) with check (true);

-- 3. "Narrowing" with GRANT. The earlier GRANT ALL (the Supabase default) still
--    stands, so authenticated can still insert, update and delete.
create table public.invoices (
  id        bigint generated always as identity primary key,
  tenant_id uuid not null,
  amount    numeric not null
);
alter table public.invoices enable row level security;
create policy invoices_read on public.invoices for select to authenticated using (true);
grant select on public.invoices to authenticated;   -- does not remove anything

-- 4. SECURITY DEFINER with no fixed search_path, callable by anyone (PUBLIC
--    has EXECUTE by default) and trusting the tenant id it is given.
create function public.invoice_total(p_tenant uuid) returns numeric
language sql
security definer
as $$ select coalesce(sum(amount), 0) from invoices where tenant_id = p_tenant $$;

-- 5. A view that runs as its owner, so RLS on the base table is skipped.
create view public.customer_emails as
  select tenant_id, email from public.customers;

-- 6. An "append-only" ledger that anyone with the default grants can rewrite.
create table public.payment_ledger (
  id        bigint generated always as identity primary key,
  tenant_id uuid not null,
  amount    numeric not null
);
comment on table public.payment_ledger is 'append-only';
alter table public.payment_ledger enable row level security;
create policy ledger_read on public.payment_ledger for select to authenticated using (true);
