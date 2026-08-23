-- Repair projects that applied 000100 before its API-role grants were made
-- explicit. Supabase can grant EXECUTE directly to anon/authenticated when a
-- function is created; revoking from PUBLIC does not remove those grants.
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

-- The existing functions were created before the corrected direct-SQL rule.
-- Replace only their authorization guards; their write semantics are unchanged.
create or replace function public.record_student_verification(
  p_user_id uuid, p_email text, p_google_sub text
) returns public.student_profiles
language plpgsql security definer set search_path = public, pg_temp as $fn$
declare v_existing public.student_profiles; v_result public.student_profiles; v_owner uuid;
begin
  if not (public.jwt_role() = 'service_role' or (public.jwt_role() = '' and current_user not in ('anon', 'authenticated'))) then
    raise exception 'record_student_verification is a service-role operation' using errcode = '42501';
  end if;
  if p_user_id is null or coalesce(p_email, '') = '' or coalesce(p_google_sub, '') = '' then
    raise exception 'record_student_verification requires user_id, email and google_sub' using errcode = '22023';
  end if;
  perform set_config('app.student_ctx', 'on', true);
  select user_id into v_owner from public.student_profiles where google_sub = p_google_sub;
  if v_owner is not null and v_owner <> p_user_id then
    perform set_config('app.student_ctx', 'off', true);
    raise exception 'google subject is already bound to another account' using errcode = '42501';
  end if;
  select * into v_existing from public.student_profiles where user_id = p_user_id;
  if v_existing.user_id is not null then
    update public.student_profiles set email = lower(p_email), google_sub = p_google_sub, ncku_verified = true, verified_at = now()
      where user_id = p_user_id returning * into v_result;
  else
    insert into public.student_profiles (user_id, email, google_sub, ncku_verified, verified_at, is_active)
      values (p_user_id, lower(p_email), p_google_sub, true, now(), true) returning * into v_result;
  end if;
  insert into public.audit_log (actor_user_id, action, target_type, target_id, organization, metadata)
    values (p_user_id, case when v_existing.user_id is null then 'student.verified' else 'student.reverified' end,
      'student_profiles', p_user_id::text, 'student_union',
      jsonb_build_object('was_verified', coalesce(v_existing.ncku_verified, false), 'is_active', v_result.is_active));
  perform set_config('app.student_ctx', 'off', true);
  return v_result;
end $fn$;

create or replace function public.set_student_active(
  p_student_user_id uuid, p_active boolean, p_reason text default null
) returns public.student_profiles
language plpgsql security definer set search_path = public, pg_temp as $fn$
declare v_before public.student_profiles; v_after public.student_profiles;
begin
  if not (public.jwt_role() = 'service_role' or public.is_admin_owner_for('student_union')
          or (public.jwt_role() = '' and current_user not in ('anon', 'authenticated'))) then
    raise exception 'student activation is restricted to student_union owners' using errcode = '42501';
  end if;
  if p_student_user_id is null or p_active is null then
    raise exception 'set_student_active requires a student and a target state' using errcode = '22023';
  end if;
  perform set_config('app.student_ctx', 'on', true);
  select * into v_before from public.student_profiles where user_id = p_student_user_id;
  if v_before.user_id is null then
    perform set_config('app.student_ctx', 'off', true);
    raise exception 'no such student' using errcode = 'P0002';
  end if;
  update public.student_profiles set is_active = p_active where user_id = p_student_user_id returning * into v_after;
  insert into public.audit_log (actor_user_id, action, target_type, target_id, organization, metadata)
    values (auth.uid(), case when p_active then 'student.reactivated' else 'student.suspended' end,
      'student_profiles', p_student_user_id::text, 'student_union',
      jsonb_build_object('was_active', v_before.is_active, 'is_active', v_after.is_active, 'reason', p_reason));
  perform set_config('app.student_ctx', 'off', true);
  return v_after;
end $fn$;

-- Service-role-only drift probe for the live suite. Any direct anon EXECUTE
-- grant is a deployment defect, even when a function body has a second guard.
create or replace function public.assert_api_function_privileges()
returns void language plpgsql security definer set search_path = public, pg_temp as $fn$
begin
  if public.jwt_role() <> 'service_role' then
    raise exception 'assert_api_function_privileges is a service-role operation' using errcode = '42501';
  end if;
  if exists (
    select 1 from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and has_function_privilege('anon', p.oid, 'EXECUTE')
  ) then
    raise exception 'anon has EXECUTE on a public function' using errcode = '42501';
  end if;
  if has_function_privilege('authenticated', 'public.record_student_verification(uuid,text,text)'::regprocedure, 'EXECUTE')
     or not has_function_privilege('authenticated', 'public.lookup_student_for_assignment(text)'::regprocedure, 'EXECUTE')
     or not has_function_privilege('authenticated', 'public.set_student_active(uuid,boolean,text)'::regprocedure, 'EXECUTE') then
    raise exception 'API function EXECUTE grants do not match the expected boundary' using errcode = '42501';
  end if;
end $fn$;
revoke execute on function public.assert_api_function_privileges() from public, anon, authenticated;
grant execute on function public.assert_api_function_privileges() to service_role;
