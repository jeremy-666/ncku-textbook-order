-- 000400 created the service-only drift probe after the global revoke block;
-- PostgreSQL's function default ACL therefore restored PUBLIC EXECUTE on it.
revoke execute on function public.assert_api_function_privileges() from public, anon, authenticated;
grant execute on function public.assert_api_function_privileges() to service_role;
