-- Supabase may grant EXECUTE directly to API roles through default privileges.
-- Removing PUBLIC alone does not remove those direct grants. Verification is
-- an edge-function/service-role operation and must not be callable by either
-- browser-facing role.
revoke execute on function public.record_student_verification(uuid, text, text) from anon, authenticated;
