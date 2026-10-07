-- Multi-tenant inventory as an append-only ledger with a derived cache.
--
--   inventory_events   the log. Insert-only, idempotent per (tenant, source, source_event_id).
--   inventory_levels   the cache. Always rebuildable from the log; never the source of truth.
--
-- Tenant isolation is enforced in the database: RLS for reads, a single
-- SECURITY DEFINER entry point for writes, and grants that match the policies.

create schema if not exists private;           -- not exposed through the API
revoke all on schema private from public, anon, authenticated;

create table public.tenants (
  id    uuid primary key,
  name  text not null
);

create table public.tenant_members (
  tenant_id uuid not null references public.tenants (id) on delete cascade,
  user_id   uuid not null references auth.users (id)    on delete cascade,
  role      text not null check (role in ('owner', 'staff', 'viewer')),
  primary key (tenant_id, user_id)
);

create table public.inventory_events (
  id               bigint generated always as identity primary key,
  tenant_id        uuid   not null references public.tenants (id),
  sku              text   not null,
  location_id      text   not null,
  qty_delta        integer not null check (qty_delta <> 0),
  reason           text   not null check (reason in ('receive', 'sale', 'return', 'adjust', 'transfer')),
  source           text   not null,             -- 'shopify', 'manual', ...
  source_event_id  text   not null,             -- provider id, makes retries harmless
  occurred_at      timestamptz not null,
  recorded_at      timestamptz not null default now(),
  recorded_by      uuid,
  unique (tenant_id, source, source_event_id)
);
comment on table public.inventory_events is 'append-only';

create table public.inventory_levels (
  tenant_id      uuid    not null references public.tenants (id),
  sku            text    not null,
  location_id    text    not null,
  on_hand        integer not null,
  last_event_id  bigint  not null,
  primary key (tenant_id, sku, location_id)
);
comment on table public.inventory_levels is 'derived from inventory_events; rebuild with private.rebuild_inventory_levels()';

-- Append-only is enforced twice: no privilege to change rows, and a trigger
-- for the roles that still could (table owner, service role).
create function private.reject_ledger_change() returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception '% on %.% is not allowed: the ledger is append-only. Post a correcting event instead.',
    tg_op, tg_table_schema, tg_table_name
    using errcode = 'insufficient_privilege';
end;
$$;

create trigger inventory_events_append_only
  before update or delete on public.inventory_events
  for each row execute function private.reject_ledger_change();

create trigger inventory_events_no_truncate
  before truncate on public.inventory_events
  for each statement execute function private.reject_ledger_change();

-- Membership check used by policies. SECURITY DEFINER so policies on
-- tenant_members do not recurse; lives in private so it is not an RPC.
create function private.is_member(p_tenant uuid, p_roles text[] default array['owner','staff','viewer'])
returns boolean
language sql stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.tenant_members m
    where m.tenant_id = p_tenant
      and m.user_id   = (select auth.uid())
      and m.role      = any (p_roles)
  )
$$;

alter table public.tenants          enable row level security;
alter table public.tenant_members   enable row level security;
alter table public.inventory_events enable row level security;
alter table public.inventory_levels enable row level security;

create policy tenants_read on public.tenants
  for select to authenticated using ((select private.is_member(id)));

create policy members_read on public.tenant_members
  for select to authenticated using ((select private.is_member(tenant_id)));

create policy events_read on public.inventory_events
  for select to authenticated using ((select private.is_member(tenant_id)));

create policy levels_read on public.inventory_levels
  for select to authenticated using ((select private.is_member(tenant_id)));

-- The one write path. The tenant comes from the caller's membership, never
-- trusted from input alone; retries of the same provider event are no-ops.
create function public.record_inventory_event(
  p_tenant uuid, p_sku text, p_location text, p_qty_delta integer, p_reason text,
  p_source text, p_source_event_id text, p_occurred_at timestamptz
) returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_id bigint;
begin
  if (select auth.uid()) is null or not private.is_member(p_tenant, array['owner','staff']) then
    raise exception 'not a writer for this tenant' using errcode = 'insufficient_privilege';
  end if;

  insert into public.inventory_events
    (tenant_id, sku, location_id, qty_delta, reason, source, source_event_id, occurred_at, recorded_by)
  values
    (p_tenant, p_sku, p_location, p_qty_delta, p_reason, p_source, p_source_event_id, p_occurred_at, (select auth.uid()))
  on conflict (tenant_id, source, source_event_id) do nothing
  returning id into v_id;

  if v_id is null then
    return 'duplicate';
  end if;

  insert into public.inventory_levels as l (tenant_id, sku, location_id, on_hand, last_event_id)
  values (p_tenant, p_sku, p_location, p_qty_delta, v_id)
  on conflict (tenant_id, sku, location_id) do update
    set on_hand = l.on_hand + excluded.on_hand,
        last_event_id = greatest(l.last_event_id, excluded.last_event_id);

  return 'recorded';
end;
$$;

comment on function public.record_inventory_event(uuid, text, text, integer, text, text, text, timestamptz) is
  'Only write path for inventory. Checks auth.uid() is owner/staff of p_tenant. audit: reviewed';

-- Rebuild the cache from the log. Order-independent: a sum does not care
-- which event arrived first, which is why the cache can always be thrown away.
create function private.rebuild_inventory_levels(p_tenant uuid) returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_rows integer;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_tenant::text, 0));

  delete from public.inventory_levels where tenant_id = p_tenant;

  insert into public.inventory_levels (tenant_id, sku, location_id, on_hand, last_event_id)
  select tenant_id, sku, location_id, sum(qty_delta)::integer, max(id)
  from public.inventory_events
  where tenant_id = p_tenant
  group by tenant_id, sku, location_id;

  get diagnostics v_rows = row_count;
  return v_rows;
end;
$$;

-- Drift check: rows where the cache disagrees with the log. Empty is healthy.
create view private.inventory_drift with (security_invoker = true) as
select coalesce(l.tenant_id, e.tenant_id)     as tenant_id,
       coalesce(l.sku, e.sku)                 as sku,
       coalesce(l.location_id, e.location_id) as location_id,
       l.on_hand                              as cached,
       e.on_hand                              as from_log
from public.inventory_levels l
full join (
  select tenant_id, sku, location_id, sum(qty_delta)::integer as on_hand
  from public.inventory_events
  group by 1, 2, 3
) e using (tenant_id, sku, location_id)
where l.on_hand is distinct from e.on_hand;

-- Grants: undo Supabase's defaults first. GRANT SELECT on its own would not
-- narrow anything; privileges only add up until they are revoked.
revoke all on public.tenants, public.tenant_members, public.inventory_events, public.inventory_levels
  from anon, authenticated;
grant select on public.tenants, public.tenant_members, public.inventory_events, public.inventory_levels
  to authenticated;

-- Functions are executable by PUBLIC by default, including SECURITY DEFINER ones.
revoke all on function public.record_inventory_event(uuid, text, text, integer, text, text, text, timestamptz)
  from public, anon, authenticated;
grant execute on function public.record_inventory_event(uuid, text, text, integer, text, text, text, timestamptz)
  to authenticated;

revoke all on all functions in schema private from public, anon, authenticated;
grant usage on schema private to service_role;
grant execute on function private.rebuild_inventory_levels(uuid) to service_role;
grant select on private.inventory_drift to service_role;
grant select on public.inventory_events, public.inventory_levels to service_role;
-- is_member is called inside policies as the querying role, so it must stay callable.
grant usage on schema private to authenticated;
grant execute on function private.is_member(uuid, text[]) to authenticated;
