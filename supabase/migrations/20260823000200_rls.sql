-- =====================================================================
-- NCKU Form System - Row Level Security
--
-- The database is the access-control boundary. Frontend routing is UX.
-- Every table below is RLS-enabled and every privilege is granted
-- explicitly after revoking Supabase permissive defaults.
--
-- V1 authorization model:
--   students      -> their own profile, their assigned forms, their own
--                    submissions. Nothing else exists for them.
--   administrators-> ORGANIZATION-SCOPED. Every admin policy is written in
--                    terms of the form organization (or the admin row
--                    organization), never in terms of "is an admin at all".
--   owner/editor  -> role levels inside one organization.
--
-- OWNERSHIP ASSUMPTION: apply this file as the same role that applied
-- 20260823000100_auth_core.sql (Supabase: `postgres`). The definer policies
-- at the bottom are created for current_user.
-- =====================================================================

alter table public.student_profiles  enable row level security;
alter table public.admin_users       enable row level security;
alter table public.forms             enable row level security;
alter table public.form_assignments  enable row level security;
alter table public.form_submissions  enable row level security;
alter table public.audit_log         enable row level security;

-- Force RLS for table owners too, so a mistakenly-owning role cannot bypass.
alter table public.student_profiles  force row level security;
alter table public.admin_users       force row level security;
alter table public.forms             force row level security;
alter table public.form_assignments  force row level security;
alter table public.form_submissions  force row level security;
-- audit_log is deliberately NOT forced: the SECURITY DEFINER audit trigger
-- and the privileged RPCs write as the table owner, and forcing RLS there
-- would silence the trail. No client role holds INSERT on it, so this grants
-- nobody anything.

-- ---------------------------------------------------------------------
-- Default privileges: future objects are denied by default.
--
-- Supabase ships default privileges that hand anon/authenticated every
-- privilege on tables created later in `public`, so a table added by a
-- future migration would be world-readable the moment it exists - before
-- anyone remembers to write a policy for it. Cancel those defaults.
--
-- ALTER DEFAULT PRIVILEGES only affects grants recorded FOR A SPECIFIC ROLE,
-- so this loops over the roles that actually create objects here and skips
-- any the current session cannot speak for (running as `postgres` you cannot
-- rewrite `supabase_admin` defaults, and pretending otherwise would produce
-- SQL whose effect silently depends on who ran it).
--
-- Note on functions: PostgreSQL default-grants EXECUTE on new functions to
-- PUBLIC. Revoking that means a future helper is unreachable until it is
-- granted explicitly - which is the intended fail-closed behaviour, and the
-- reason every helper in auth_core.sql carries its own explicit grant.
-- Types are deliberately left alone: PUBLIC USAGE on a new enum is what lets
-- PostgREST cast request values, and revoking it breaks clients without
-- protecting anything.
-- ---------------------------------------------------------------------
do $do$
declare
  v_role text;
  v_done text[] := '{}';
begin
  foreach v_role in array array[current_user, 'postgres', 'supabase_admin'] loop
    continue when v_role = any (v_done);
    continue when not exists (select 1 from pg_roles where rolname = v_role);
    continue when not pg_has_role(current_user, v_role, 'USAGE');
    v_done := v_done || v_role;

    execute format(
      'alter default privileges for role %I in schema public revoke all on tables from anon, authenticated', v_role);
    execute format(
      'alter default privileges for role %I in schema public revoke all on sequences from anon, authenticated', v_role);
    execute format(
      'alter default privileges for role %I in schema public revoke all on functions from anon, authenticated', v_role);
    execute format(
      'alter default privileges for role %I in schema public revoke execute on functions from public', v_role);

    raise notice 'default privileges revoked for role %', v_role;
  end loop;
end $do$;

-- ---------------------------------------------------------------------
-- Table privileges: revoke Supabase defaults, then grant narrowly.
-- anon (logged-out) gets nothing anywhere.
-- ---------------------------------------------------------------------
revoke all on public.student_profiles from anon, authenticated;
revoke all on public.admin_users      from anon, authenticated;
revoke all on public.forms            from anon, authenticated;
revoke all on public.form_assignments from anon, authenticated;
revoke all on public.form_submissions from anon, authenticated;
revoke all on public.audit_log        from anon, authenticated;

-- Students may only ever write department/year. ncku_verified, is_active,
-- email and google_sub are not grantable to clients at all - this is a
-- privilege check, enforced before RLS and before any trigger. Administrators
-- do not hold UPDATE here either: suspension goes through set_student_active().
grant select                          on public.student_profiles to authenticated;
grant update (department, year)       on public.student_profiles to authenticated;

grant select, insert, update          on public.admin_users      to authenticated;
grant select, insert, update, delete  on public.forms            to authenticated;
grant select, insert, delete          on public.form_assignments to authenticated;
grant select, insert, update          on public.form_submissions to authenticated;
grant select                          on public.audit_log        to authenticated;

-- ---------------------------------------------------------------------
-- student_profiles
--
-- Student privacy is least-privilege: an administrator sees a student only
-- because that student is assigned to one of their own organization forms.
-- A Liwen administrator does not receive the university roster merely for
-- being an administrator, and never sees a student who only ever dealt with
-- the Student Union.
-- ---------------------------------------------------------------------
drop policy if exists student_profiles_select_own           on public.student_profiles;
drop policy if exists student_profiles_select_admin         on public.student_profiles;
drop policy if exists student_profiles_select_shared_admin  on public.student_profiles;
drop policy if exists student_profiles_update_own           on public.student_profiles;

create policy student_profiles_select_own on public.student_profiles
  for select to authenticated
  using (user_id = auth.uid());

create policy student_profiles_select_shared_admin on public.student_profiles
  for select to authenticated
  using (public.admin_shares_student(user_id));

-- Own row only, and only while the account is verified + active. A suspended
-- student cannot even edit their own department/year.
create policy student_profiles_update_own on public.student_profiles
  for update to authenticated
  using (user_id = auth.uid() and ncku_verified and is_active)
  with check (user_id = auth.uid());

-- No INSERT and no DELETE policy: student rows are created by the
-- verify-ncku-student edge function through record_student_verification(),
-- and retired by suspension, never by a client statement.

-- ---------------------------------------------------------------------
-- admin_users
-- Students get zero rows here - not by hiding, but by policy.
-- Owners administer their OWN organization only.
-- ---------------------------------------------------------------------
drop policy if exists admin_users_select_self  on public.admin_users;
drop policy if exists admin_users_select_owner on public.admin_users;
drop policy if exists admin_users_insert_owner on public.admin_users;
drop policy if exists admin_users_update_owner on public.admin_users;

-- Every admin can read their own record (needed for routing / role display).
create policy admin_users_select_self on public.admin_users
  for select to authenticated
  using (user_id = auth.uid());

create policy admin_users_select_owner on public.admin_users
  for select to authenticated
  using (public.is_admin_owner_for(organization));

-- Only an active owner of THAT organization may add or change its
-- administrators. The WITH CHECK is what stops an owner minting an
-- administrator for the other organization; the guard trigger additionally
-- blocks self-promotion, self-reactivation, and any user_id rewrite.
create policy admin_users_insert_owner on public.admin_users
  for insert to authenticated
  with check (public.is_admin_owner_for(organization));

create policy admin_users_update_owner on public.admin_users
  for update to authenticated
  using (public.is_admin_owner_for(organization))
  with check (public.is_admin_owner_for(organization));

-- ---------------------------------------------------------------------
-- forms
-- ---------------------------------------------------------------------
drop policy if exists forms_select_assigned on public.forms;
drop policy if exists forms_select_admin    on public.forms;
drop policy if exists forms_insert_admin    on public.forms;
drop policy if exists forms_update_admin    on public.forms;
drop policy if exists forms_delete_owner    on public.forms;

-- A student sees a form only if a row in form_assignments says so, and the
-- form has left draft. No assignment -> the row does not exist for them.
create policy forms_select_assigned on public.forms
  for select to authenticated
  using (status <> 'draft' and public.has_form_assignment(id));

create policy forms_select_admin on public.forms
  for select to authenticated
  using (public.is_active_admin_for(organization));

create policy forms_insert_admin on public.forms
  for insert to authenticated
  with check (public.is_active_admin_for(organization) and created_by = auth.uid());

create policy forms_update_admin on public.forms
  for update to authenticated
  using (public.is_active_admin_for(organization))
  with check (public.is_active_admin_for(organization));

create policy forms_delete_owner on public.forms
  for delete to authenticated
  using (public.is_admin_owner_for(organization));

-- ---------------------------------------------------------------------
-- form_assignments
-- These rows carry no organization of their own; the form supplies it.
-- ---------------------------------------------------------------------
drop policy if exists form_assignments_select_own   on public.form_assignments;
drop policy if exists form_assignments_select_admin on public.form_assignments;
drop policy if exists form_assignments_insert_admin on public.form_assignments;
drop policy if exists form_assignments_delete_admin on public.form_assignments;

create policy form_assignments_select_own on public.form_assignments
  for select to authenticated
  using (student_user_id = auth.uid() and public.is_verified_student());

create policy form_assignments_select_admin on public.form_assignments
  for select to authenticated
  using (public.admin_can_access_form(form_id));

create policy form_assignments_insert_admin on public.form_assignments
  for insert to authenticated
  with check (public.admin_can_access_form(form_id) and assigned_by = auth.uid());

create policy form_assignments_delete_admin on public.form_assignments
  for delete to authenticated
  using (public.admin_can_access_form(form_id));

-- ---------------------------------------------------------------------
-- form_submissions
-- ---------------------------------------------------------------------
drop policy if exists form_submissions_select_own   on public.form_submissions;
drop policy if exists form_submissions_select_admin on public.form_submissions;
drop policy if exists form_submissions_insert_own   on public.form_submissions;
drop policy if exists form_submissions_update_own   on public.form_submissions;

create policy form_submissions_select_own on public.form_submissions
  for select to authenticated
  using (student_user_id = auth.uid() and public.is_verified_student());

create policy form_submissions_select_admin on public.form_submissions
  for select to authenticated
  using (public.admin_can_access_form(form_id));

-- A submission may only be created for a form this student is actually
-- assigned to, and only while that form is accepting submissions.
create policy form_submissions_insert_own on public.form_submissions
  for insert to authenticated
  with check (
    student_user_id = auth.uid()
    and public.has_form_assignment(form_id)
    and public.form_accepts_submissions(form_id)
  );

-- Editing requires the assignment to still exist and the form to still be
-- open. Identity columns and timestamps are pinned by the guard trigger, so
-- an update cannot become a submission for a different form or student.
create policy form_submissions_update_own on public.form_submissions
  for update to authenticated
  using (
    student_user_id = auth.uid()
    and public.is_verified_student()
    and public.has_form_assignment(form_id)
    and public.form_accepts_submissions(form_id)
  )
  with check (
    student_user_id = auth.uid()
    and public.has_form_assignment(form_id)
    and public.form_accepts_submissions(form_id)
  );

-- No student DELETE: withdrawing an order is an admin/business action.
-- No admin UPDATE/DELETE either in V1 - administrators read submissions.

-- ---------------------------------------------------------------------
-- audit_log - readable by the owning organization, writable by nobody but
-- the triggers and the privileged RPCs. Entries with a NULL organization
-- are readable by no client at all.
-- ---------------------------------------------------------------------
drop policy if exists audit_log_select_admin on public.audit_log;
drop policy if exists audit_log_select_org   on public.audit_log;

create policy audit_log_select_org on public.audit_log
  for select to authenticated
  using (organization is not null and organization = public.current_admin_org());

-- ---------------------------------------------------------------------
-- Definer policies for the migration owner.
--
-- The authorization kernel is a set of SECURITY DEFINER helpers that must be
-- able to READ the authorization tables, and two privileged RPCs that must be
-- able to WRITE student_profiles. Under FORCE ROW LEVEL SECURITY the owning
-- role is subject to policies like anyone else unless it holds BYPASSRLS -
-- an attribute that differs between deployments. Rather than dropping FORCE
-- (which would weaken the table for every role), grant the owner exactly what
-- the kernel needs:
--
--   * SELECT on the authorization tables - the helpers do nothing but read.
--   * INSERT/UPDATE on student_profiles ONLY while a privileged RPC has set
--     the transaction-local marker app.student_ctx. Nothing a client can
--     reach sets it: PostgREST connects as anon/authenticated/service_role,
--     none of which these policies apply to, and none of which can call
--     set_config on this GUC through the API.
--
-- If the owning role does hold BYPASSRLS these policies are simply never
-- consulted; the deployment behaves identically either way.
-- ---------------------------------------------------------------------
do $do$
declare
  v_owner text := current_user;
  v_table text;
begin
  foreach v_table in array array['student_profiles', 'admin_users', 'forms', 'form_assignments'] loop
    execute format('drop policy if exists %I on public.%I', v_table || '_definer_read', v_table);
    execute format(
      'create policy %I on public.%I for select to %I using (true)',
      v_table || '_definer_read', v_table, v_owner);
  end loop;

  execute format('drop policy if exists student_profiles_definer_write on public.student_profiles');
  execute format(
    'create policy student_profiles_definer_write on public.student_profiles'
    ' for all to %I'
    ' using (public.privileged_student_ctx())'
    ' with check (public.privileged_student_ctx())',
    v_owner);

  raise notice 'definer policies created for role %', v_owner;
end $do$;

-- ---------------------------------------------------------------------
-- Retired helper: is_admin_owner() answered "an owner of any organization",
-- which is exactly the question this migration stopped asking. Dropped last,
-- once nothing depends on it.
-- ---------------------------------------------------------------------
drop function if exists public.is_admin_owner();
