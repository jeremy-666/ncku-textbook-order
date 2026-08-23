-- =====================================================================
-- NCKU Form System - authentication / authorization core
-- Phase C: schema, helper functions, guards, audit triggers, RPCs.
--
-- Security model:
--   * auth.users            -> authentication only (Supabase Auth)
--   * public.student_profiles / public.admin_users -> authorization
--   * NOTHING in user_metadata is ever consulted for authorization.
--   * ncku_verified / is_active / role are writable by privileged
--     operations only, never by a client UPDATE.
--
-- Organization model (V1 product decision):
--   Administrators are ORGANIZATION-SCOPED. A liwen admin manages liwen
--   forms; a student_union admin manages student_union forms. owner and
--   editor are role levels *inside* one organization, not global powers.
--   The only deliberately cross-organization operation is student
--   suspension, which is restricted to student_union owners.
--
-- OWNERSHIP ASSUMPTION (load-bearing - see docs/SETUP.md):
--   This file must be applied by the role that should own these objects.
--   On Supabase that is `postgres` (the role the SQL editor, the CLI and
--   `db push` use). Every SECURITY DEFINER function below therefore runs as
--   `postgres`. Because those tables also carry FORCE ROW LEVEL SECURITY,
--   20260823000200_rls.sql grants `current_user` an explicit read policy on
--   the authorization tables plus a write policy gated on the transaction
--   marker below - so the authorization kernel keeps working whether or not
--   the owning role happens to hold BYPASSRLS on a given deployment.
-- =====================================================================

create extension if not exists "pgcrypto";

-- ---------------------------------------------------------------------
-- Enums
-- ---------------------------------------------------------------------
do $do$ begin
  create type public.admin_organization as enum ('liwen', 'student_union');
exception when duplicate_object then null; end $do$;

do $do$ begin
  create type public.admin_role as enum ('editor', 'owner');
exception when duplicate_object then null; end $do$;

do $do$ begin
  create type public.form_status as enum ('draft', 'open', 'closed');
exception when duplicate_object then null; end $do$;

do $do$ begin
  create type public.submission_status as enum ('draft', 'submitted');
exception when duplicate_object then null; end $do$;

-- ---------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------

-- Student authorization record. Created ONLY by the verify-ncku-student
-- edge function (service_role) after a Google ID token proved hd=gs.ncku.edu.tw.
create table if not exists public.student_profiles (
  user_id       uuid primary key references auth.users (id) on delete cascade,
  email         text not null,
  google_sub    text unique,                       -- stable Google subject, not email
  department    text,
  year          integer check (year between 1 and 7),
  ncku_verified boolean not null default false,
  verified_at   timestamptz,
  is_active     boolean not null default true,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);
create index if not exists student_profiles_email_idx on public.student_profiles (lower(email));

-- Administrator allowlist. Provisioned by a trusted operator (see docs/SETUP.md).
create table if not exists public.admin_users (
  user_id      uuid primary key references auth.users (id) on delete cascade,
  organization public.admin_organization not null,
  display_name text not null,
  role         public.admin_role not null default 'editor',
  is_active    boolean not null default true,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

create table if not exists public.forms (
  id           uuid primary key default gen_random_uuid(),
  title        text not null,
  description  text,
  organization public.admin_organization not null,
  status       public.form_status not null default 'draft',
  fields       jsonb not null default '[]'::jsonb,
  opens_at     timestamptz,
  closes_at    timestamptz,
  created_by   uuid references auth.users (id) on delete set null,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

create table if not exists public.form_assignments (
  id               uuid primary key default gen_random_uuid(),
  form_id          uuid not null references public.forms (id) on delete cascade,
  student_user_id  uuid not null references auth.users (id) on delete cascade,
  assigned_by      uuid references auth.users (id) on delete set null,
  created_at       timestamptz not null default now(),
  unique (form_id, student_user_id)
);
create index if not exists form_assignments_student_idx on public.form_assignments (student_user_id);

create table if not exists public.form_submissions (
  id               uuid primary key default gen_random_uuid(),
  form_id          uuid not null references public.forms (id) on delete cascade,
  student_user_id  uuid not null references auth.users (id) on delete cascade,
  answers          jsonb not null default '{}'::jsonb,
  status           public.submission_status not null default 'draft',
  submitted_at     timestamptz,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  unique (form_id, student_user_id)
);
create index if not exists form_submissions_form_idx on public.form_submissions (form_id);

-- Single audit trail. Written by triggers and privileged RPCs, never by clients.
-- organization scopes each entry so one vendor administrator cannot read the
-- other vendor form history. Entries with a NULL organization are visible to
-- nobody through the API - that is deliberate fail-closed behaviour.
create table if not exists public.audit_log (
  id            bigint generated always as identity primary key,
  actor_user_id uuid,
  action        text not null,
  target_type   text not null,
  target_id     text,
  organization  public.admin_organization,
  metadata      jsonb not null default '{}'::jsonb,
  created_at    timestamptz not null default now()
);
alter table public.audit_log add column if not exists organization public.admin_organization;
create index if not exists audit_log_created_idx on public.audit_log (created_at desc);
create index if not exists audit_log_org_idx on public.audit_log (organization, created_at desc);

-- ---------------------------------------------------------------------
-- Authorization helper functions
-- SECURITY DEFINER so RLS policies can consult the authorization tables
-- without recursing into their own policies. search_path is pinned on
-- every one of them, including the plain-invoker helpers.
-- ---------------------------------------------------------------------

-- The role PostgREST is acting as for this request: authenticated for a
-- browser session, service_role for the edge function, empty for direct SQL.
-- Self-contained rather than relying on a deprecated Supabase role helper.
create or replace function public.jwt_role()
returns text
language sql stable set search_path = public, pg_temp as $fn$
  select coalesce(nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role', '');
$fn$;

-- The organization of the calling administrator, or NULL when the caller is
-- not an active administrator. Every org-scoped policy is written in terms of
-- this, so "not an admin" and "admin of the other org" fail the same way.
--
-- Named current_admin_org() rather than admin_organization(): that identifier
-- is already the enum type, and a zero-argument function sharing a type name
-- collides with cast syntax.
create or replace function public.current_admin_org()
returns public.admin_organization
language sql stable security definer set search_path = public, pg_temp as $fn$
  select a.organization from public.admin_users a
  where a.user_id = auth.uid() and a.is_active;
$fn$;

create or replace function public.is_active_admin()
returns boolean
language sql stable security definer set search_path = public, pg_temp as $fn$
  select exists (
    select 1 from public.admin_users a
    where a.user_id = auth.uid() and a.is_active
  );
$fn$;

-- Active administrator OF A PARTICULAR ORGANIZATION. A NULL argument (a row
-- with no organization) is false, never NULL-permissive.
create or replace function public.is_active_admin_for(p_org public.admin_organization)
returns boolean
language sql stable security definer set search_path = public, pg_temp as $fn$
  select p_org is not null and exists (
    select 1 from public.admin_users a
    where a.user_id = auth.uid() and a.is_active and a.organization = p_org
  );
$fn$;

create or replace function public.is_admin_owner_for(p_org public.admin_organization)
returns boolean
language sql stable security definer set search_path = public, pg_temp as $fn$
  select p_org is not null and exists (
    select 1 from public.admin_users a
    where a.user_id = auth.uid() and a.is_active and a.role = 'owner' and a.organization = p_org
  );
$fn$;

create or replace function public.is_verified_student()
returns boolean
language sql stable security definer set search_path = public, pg_temp as $fn$
  select exists (
    select 1 from public.student_profiles s
    where s.user_id = auth.uid() and s.ncku_verified and s.is_active
  );
$fn$;

create or replace function public.has_form_assignment(p_form_id uuid)
returns boolean
language sql stable security definer set search_path = public, pg_temp as $fn$
  select public.is_verified_student() and exists (
    select 1 from public.form_assignments fa
    where fa.form_id = p_form_id and fa.student_user_id = auth.uid()
  );
$fn$;

create or replace function public.form_accepts_submissions(p_form_id uuid)
returns boolean
language sql stable security definer set search_path = public, pg_temp as $fn$
  select exists (
    select 1 from public.forms f
    where f.id = p_form_id
      and f.status = 'open'
      and (f.opens_at  is null or f.opens_at  <= now())
      and (f.closes_at is null or f.closes_at >  now())
  );
$fn$;

-- Admin-side form scoping: may the caller act on this form organization?
-- Used by form_assignments and form_submissions, whose own rows carry no
-- organization - the form is the single source of truth for that.
create or replace function public.admin_can_access_form(p_form_id uuid)
returns boolean
language sql stable security definer set search_path = public, pg_temp as $fn$
  select exists (
    select 1 from public.forms f
    join public.admin_users a on a.user_id = auth.uid() and a.is_active
    where f.id = p_form_id and f.organization = a.organization
  );
$fn$;

create or replace function public.admin_owns_form(p_form_id uuid)
returns boolean
language sql stable security definer set search_path = public, pg_temp as $fn$
  select exists (
    select 1 from public.forms f
    join public.admin_users a on a.user_id = auth.uid() and a.is_active and a.role = 'owner'
    where f.id = p_form_id and f.organization = a.organization
  );
$fn$;

-- Student privacy: an administrator may see a student profile only because
-- that student is assigned to one of THEIR organization forms. There is no
-- "every active admin sees the whole roster" path any more.
create or replace function public.admin_shares_student(p_student_user_id uuid)
returns boolean
language sql stable security definer set search_path = public, pg_temp as $fn$
  select exists (
    select 1
    from public.form_assignments fa
    join public.forms f on f.id = fa.form_id
    join public.admin_users a on a.user_id = auth.uid() and a.is_active
    where fa.student_user_id = p_student_user_id
      and f.organization = a.organization
  );
$fn$;

-- Transaction-local marker set only by the privileged student RPCs below.
-- 20260823000200_rls.sql grants the migration owner a write policy on
-- student_profiles gated on this, so those RPCs work under FORCE ROW LEVEL
-- SECURITY whether or not the owning role holds BYPASSRLS.
create or replace function public.privileged_student_ctx()
returns boolean
language sql stable set search_path = public, pg_temp as $fn$
  select coalesce(current_setting('app.student_ctx', true), '') = 'on';
$fn$;

revoke all on function public.jwt_role()                                     from public;
revoke all on function public.current_admin_org()                            from public;
revoke all on function public.is_active_admin()                              from public;
revoke all on function public.is_active_admin_for(public.admin_organization) from public;
revoke all on function public.is_admin_owner_for(public.admin_organization)  from public;
revoke all on function public.is_verified_student()                          from public;
revoke all on function public.has_form_assignment(uuid)                      from public;
revoke all on function public.form_accepts_submissions(uuid)                 from public;
revoke all on function public.admin_can_access_form(uuid)                    from public;
revoke all on function public.admin_owns_form(uuid)                          from public;
revoke all on function public.admin_shares_student(uuid)                     from public;
revoke all on function public.privileged_student_ctx()                     from public;

grant execute on function public.jwt_role()                                     to authenticated;
grant execute on function public.current_admin_org()                            to authenticated;
grant execute on function public.is_active_admin()                              to authenticated;
grant execute on function public.is_active_admin_for(public.admin_organization) to authenticated;
grant execute on function public.is_admin_owner_for(public.admin_organization)  to authenticated;
grant execute on function public.is_verified_student()                          to authenticated;
grant execute on function public.has_form_assignment(uuid)                      to authenticated;
grant execute on function public.form_accepts_submissions(uuid)                 to authenticated;
grant execute on function public.admin_can_access_form(uuid)                    to authenticated;
grant execute on function public.admin_owns_form(uuid)                          to authenticated;
grant execute on function public.admin_shares_student(uuid)                     to authenticated;

-- ---------------------------------------------------------------------
-- updated_at maintenance
-- ---------------------------------------------------------------------
create or replace function public.tg_touch_updated_at()
returns trigger language plpgsql set search_path = public, pg_temp as $fn$
begin
  new.updated_at := now();
  return new;
end $fn$;

drop trigger if exists touch_student_profiles on public.student_profiles;
create trigger touch_student_profiles before update on public.student_profiles
  for each row execute function public.tg_touch_updated_at();

drop trigger if exists touch_admin_users on public.admin_users;
create trigger touch_admin_users before update on public.admin_users
  for each row execute function public.tg_touch_updated_at();

drop trigger if exists touch_forms on public.forms;
create trigger touch_forms before update on public.forms
  for each row execute function public.tg_touch_updated_at();

drop trigger if exists touch_form_submissions on public.form_submissions;
create trigger touch_form_submissions before update on public.form_submissions
  for each row execute function public.tg_touch_updated_at();

-- ---------------------------------------------------------------------
-- Privilege-escalation guards (defence in depth behind the column grants
-- in the RLS migration; column grants reject first, these catch anything a
-- future grant might let through - including UPSERT, whose ON CONFLICT DO
-- UPDATE branch fires the BEFORE UPDATE trigger).
-- ---------------------------------------------------------------------

-- A student may never change their own verification / activation state
-- or their identity columns.
--
-- The privileged RPCs run SECURITY DEFINER but keep the caller request
-- claims, so an administrator suspending a student still looks like
-- jwt_role() = 'authenticated' here. Without the app.student_ctx exemption
-- this trigger would silently revert set_student_active() and suspension
-- would appear to succeed while changing nothing.
create or replace function public.tg_student_profiles_guard()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $fn$
begin
  if public.jwt_role() = 'authenticated' and not public.privileged_student_ctx() then
    new.user_id       := old.user_id;
    new.email         := old.email;
    new.google_sub    := old.google_sub;
    new.ncku_verified := old.ncku_verified;
    new.verified_at   := old.verified_at;
    new.is_active     := old.is_active;
    new.created_at    := old.created_at;
  end if;
  return new;
end $fn$;

drop trigger if exists guard_student_profiles on public.student_profiles;
create trigger guard_student_profiles before update on public.student_profiles
  for each row execute function public.tg_student_profiles_guard();

-- Administrator identity is immutable, and nobody may edit their own role or
-- activation state - owner included.
--
-- The self-check keys on OLD.user_id: the subject of an UPDATE is the row that
-- already exists, not whatever user_id the statement is trying to write. An
-- earlier version tested NEW.user_id, so writing user_id and role in the same
-- statement skipped the self-check entirely. Rewriting user_id is now refused
-- outright, which closes that path and the row-hijack it enabled.
create or replace function public.tg_admin_users_guard()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $fn$
begin
  if public.jwt_role() <> 'authenticated' then
    return new;
  end if;

  if new.user_id is distinct from old.user_id then
    raise exception 'administrator identity (user_id) is immutable'
      using errcode = '42501';
  end if;

  if new.organization is distinct from old.organization then
    raise exception 'administrator organization is immutable'
      using errcode = '42501';
  end if;

  if old.user_id = auth.uid()
     and (new.role is distinct from old.role
          or new.is_active is distinct from old.is_active) then
    raise exception 'administrators cannot change their own role or activation state'
      using errcode = '42501';
  end if;

  return new;
end $fn$;

drop trigger if exists guard_admin_users on public.admin_users;
create trigger guard_admin_users before update on public.admin_users
  for each row execute function public.tg_admin_users_guard();

-- A form never changes identity, organization or authorship. Without this an
-- administrator could rewrite created_by (destroying attribution) or move a
-- form into the other organization on its way out of their own reach.
create or replace function public.tg_forms_guard()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $fn$
begin
  if public.jwt_role() = 'authenticated' then
    if new.id is distinct from old.id then
      raise exception 'form id is immutable' using errcode = '42501';
    end if;
    if new.organization is distinct from old.organization then
      raise exception 'form organization is immutable' using errcode = '42501';
    end if;
    if new.created_by is distinct from old.created_by then
      raise exception 'form authorship is immutable' using errcode = '42501';
    end if;
    new.created_at := old.created_at;
  end if;
  return new;
end $fn$;

drop trigger if exists guard_forms on public.forms;
create trigger guard_forms before update on public.forms
  for each row execute function public.tg_forms_guard();

-- Submission identity is immutable and its timestamps are server-controlled:
-- a client cannot backdate an order, cannot move a submission to another form,
-- and cannot re-point it at another student.
create or replace function public.tg_form_submissions_guard()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $fn$
begin
  if public.jwt_role() <> 'authenticated' then
    return new;
  end if;

  if tg_op = 'UPDATE' then
    if new.id is distinct from old.id
       or new.form_id is distinct from old.form_id
       or new.student_user_id is distinct from old.student_user_id then
      raise exception 'submission identity is immutable' using errcode = '42501';
    end if;
    new.created_at   := old.created_at;
    new.submitted_at := case
      when new.status = 'submitted' then coalesce(old.submitted_at, now())
      else null
    end;
  else
    new.created_at   := now();
    new.updated_at   := now();
    new.submitted_at := case when new.status = 'submitted' then now() else null end;
  end if;

  return new;
end $fn$;

drop trigger if exists guard_form_submissions on public.form_submissions;
create trigger guard_form_submissions before insert or update on public.form_submissions
  for each row execute function public.tg_form_submissions_guard();

-- ---------------------------------------------------------------------
-- Audit triggers - clients never write audit_log directly.
--
-- Scope note: forms, form_assignments and admin_users carry full row
-- snapshots because that is administrative configuration, and it is now
-- readable only by the owning organization. student_profiles and
-- form_submissions deliberately have NO snapshot trigger - copying every
-- student answer and personal detail into a second table would widen the
-- blast radius of any audit_log read for no stated requirement. Student
-- verification and suspension are audited as narrow events by the
-- privileged RPCs below instead.
-- ---------------------------------------------------------------------
create or replace function public.tg_audit()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $fn$
declare
  v_old       jsonb;
  v_new       jsonb;
  v_row       jsonb;
  v_target_id text;
  v_org       public.admin_organization;
begin
  -- Rows are captured as jsonb so one trigger serves tables with different
  -- primary keys (forms.id vs admin_users.user_id) and so the branch for the
  -- record that does not exist for this operation is never compiled.
  if tg_op = 'DELETE' then
    v_old := to_jsonb(old);
  elsif tg_op = 'UPDATE' then
    v_old := to_jsonb(old);
    v_new := to_jsonb(new);
  else
    v_new := to_jsonb(new);
  end if;

  v_row := coalesce(v_new, v_old);
  v_target_id := coalesce(v_row ->> 'id', v_row ->> 'user_id');

  if tg_table_name in ('forms', 'admin_users') then
    v_org := (v_row ->> 'organization')::public.admin_organization;
  elsif tg_table_name = 'form_assignments' then
    select f.organization into v_org from public.forms f
    where f.id = (v_row ->> 'form_id')::uuid;
    -- A cascade from a deleted form leaves nothing to join to; fall back to
    -- the acting administrator organization rather than writing an entry no
    -- administrator can ever read.
    v_org := coalesce(v_org, public.current_admin_org());
  end if;

  -- NOT jsonb_strip_nulls: stripping erases exactly the transitions worth
  -- auditing (a column set to NULL simply vanishes from the diff). Only the
  -- side that does not exist for this operation is left as JSON null.
  insert into public.audit_log (actor_user_id, action, target_type, target_id, organization, metadata)
  values (
    auth.uid(),
    lower(tg_table_name) || '.' || lower(tg_op),
    tg_table_name,
    v_target_id,
    v_org,
    jsonb_build_object('old', v_old, 'new', v_new)
  );
  return null;
end $fn$;

drop trigger if exists audit_forms on public.forms;
create trigger audit_forms after insert or update or delete on public.forms
  for each row execute function public.tg_audit();

drop trigger if exists audit_form_assignments on public.form_assignments;
create trigger audit_form_assignments after insert or update or delete on public.form_assignments
  for each row execute function public.tg_audit();

drop trigger if exists audit_admin_users on public.admin_users;
create trigger audit_admin_users after insert or update or delete on public.admin_users
  for each row execute function public.tg_audit();

-- ---------------------------------------------------------------------
-- Privileged operations (RPC)
--
-- Everything a client is NOT allowed to do with a plain UPDATE - proving an
-- NCKU identity, finding a student to assign, suspending a student - happens
-- here: one auditable statement behind an explicit authorization check.
-- ---------------------------------------------------------------------

-- Called by the verify-ncku-student edge function (service_role) once a
-- Google ID token has been verified AND bound to the caller. p_user_id comes
-- from the caller access token inside that function, never from its request
-- body. The profile write and the audit entry share one transaction, so a
-- failed audit cannot leave an unrecorded eligibility grant behind.
create or replace function public.record_student_verification(
  p_user_id    uuid,
  p_email      text,
  p_google_sub text
)
returns public.student_profiles
language plpgsql security definer set search_path = public, pg_temp as $fn$
declare
  v_existing public.student_profiles;
  v_result   public.student_profiles;
  v_owner    uuid;
begin
  -- Direct SQL is trusted only when it is not executing as an API role.
  if not (
    public.jwt_role() = 'service_role'
    or (public.jwt_role() = '' and current_user not in ('anon', 'authenticated'))
  ) then
    raise exception 'record_student_verification is a service-role operation'
      using errcode = '42501';
  end if;
  if p_user_id is null or coalesce(p_email, '') = '' or coalesce(p_google_sub, '') = '' then
    raise exception 'record_student_verification requires user_id, email and google_sub'
      using errcode = '22023';
  end if;

  perform set_config('app.student_ctx', 'on', true);

  -- One Google subject belongs to exactly one Supabase user, forever.
  select user_id into v_owner from public.student_profiles where google_sub = p_google_sub;
  if v_owner is not null and v_owner <> p_user_id then
    perform set_config('app.student_ctx', 'off', true);
    raise exception 'google subject is already bound to another account'
      using errcode = '42501';
  end if;

  select * into v_existing from public.student_profiles where user_id = p_user_id;

  if v_existing.user_id is not null then
    -- is_active is deliberately never written here: re-authenticating must
    -- not lift a suspension.
    update public.student_profiles
       set email         = lower(p_email),
           google_sub    = p_google_sub,
           ncku_verified = true,
           verified_at   = now()
     where user_id = p_user_id
    returning * into v_result;
  else
    insert into public.student_profiles (user_id, email, google_sub, ncku_verified, verified_at, is_active)
    values (p_user_id, lower(p_email), p_google_sub, true, now(), true)
    returning * into v_result;
  end if;

  insert into public.audit_log (actor_user_id, action, target_type, target_id, organization, metadata)
  values (
    p_user_id,
    case when v_existing.user_id is null then 'student.verified' else 'student.reverified' end,
    'student_profiles',
    p_user_id::text,
    'student_union',
    jsonb_build_object('was_verified', coalesce(v_existing.ncku_verified, false), 'is_active', v_result.is_active)
  );

  perform set_config('app.student_ctx', 'off', true);
  return v_result;
end $fn$;

-- Assignment lookup. An administrator needs to turn an email address into a
-- user id to assign a form, but must not receive the roster to do it: this
-- returns one exact-match row and nothing else - no department, no year, no
-- name, no enumeration, no partial matching.
create or replace function public.lookup_student_for_assignment(p_email text)
returns table (user_id uuid, assignable boolean)
language plpgsql security definer set search_path = public, pg_temp as $fn$
begin
  if not public.is_active_admin() then
    raise exception 'student lookup is restricted to active administrators'
      using errcode = '42501';
  end if;

  perform set_config('app.student_ctx', 'on', true);

  return query
    select s.user_id, (s.ncku_verified and s.is_active) as assignable
    from public.student_profiles s
    where coalesce(trim(p_email), '') <> ''
      and lower(s.email) = lower(trim(p_email));

  perform set_config('app.student_ctx', 'off', true);
end $fn$;

-- Student suspension / reactivation.
--
-- Least-privileged reading of the product decision: suspending a student is a
-- university-side action over university-wide data, so it belongs to
-- student_union owners. A Liwen administrator - of any role - cannot suspend,
-- reactivate, or discover students this way.
create or replace function public.set_student_active(
  p_student_user_id uuid,
  p_active          boolean,
  p_reason          text default null
)
returns public.student_profiles
language plpgsql security definer set search_path = public, pg_temp as $fn$
declare
  v_before public.student_profiles;
  v_after  public.student_profiles;
begin
  if not (
    public.jwt_role() = 'service_role'
    or public.is_admin_owner_for('student_union')
    or (public.jwt_role() = '' and current_user not in ('anon', 'authenticated'))
  ) then
    raise exception 'student activation is restricted to student_union owners'
      using errcode = '42501';
  end if;
  if p_student_user_id is null or p_active is null then
    raise exception 'set_student_active requires a student and a target state'
      using errcode = '22023';
  end if;

  perform set_config('app.student_ctx', 'on', true);

  select * into v_before from public.student_profiles where user_id = p_student_user_id;
  if v_before.user_id is null then
    perform set_config('app.student_ctx', 'off', true);
    raise exception 'no such student' using errcode = 'P0002';
  end if;

  update public.student_profiles
     set is_active = p_active
   where user_id = p_student_user_id
  returning * into v_after;

  insert into public.audit_log (actor_user_id, action, target_type, target_id, organization, metadata)
  values (
    auth.uid(),
    case when p_active then 'student.reactivated' else 'student.suspended' end,
    'student_profiles',
    p_student_user_id::text,
    'student_union',
    jsonb_build_object('was_active', v_before.is_active, 'is_active', v_after.is_active, 'reason', p_reason)
  );

  perform set_config('app.student_ctx', 'off', true);
  return v_after;
end $fn$;

-- Supabase can grant EXECUTE directly to API roles through default privileges.
-- Remove those grants from every function created above, then expose only the
-- functions needed by RLS or the intended RPC callers.
revoke execute on all functions in schema public from public, anon, authenticated;

grant execute on function public.current_admin_org()                                      to authenticated;
grant execute on function public.is_active_admin()                                       to authenticated;
grant execute on function public.is_active_admin_for(public.admin_organization)          to authenticated;
grant execute on function public.is_admin_owner_for(public.admin_organization)           to authenticated;
grant execute on function public.is_verified_student()                                   to authenticated;
grant execute on function public.has_form_assignment(uuid)                               to authenticated;
grant execute on function public.form_accepts_submissions(uuid)                          to authenticated;
grant execute on function public.admin_can_access_form(uuid)                             to authenticated;
grant execute on function public.admin_owns_form(uuid)                                   to authenticated;
grant execute on function public.admin_shares_student(uuid)                              to authenticated;
grant execute on function public.privileged_student_ctx()                                to authenticated;
grant execute on function public.lookup_student_for_assignment(text)                     to authenticated;
grant execute on function public.set_student_active(uuid, boolean, text)                 to authenticated, service_role;
grant execute on function public.record_student_verification(uuid, text, text)           to service_role;
