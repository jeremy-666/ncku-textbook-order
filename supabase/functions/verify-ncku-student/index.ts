// Edge function: verify-ncku-student
//
// Turns a proven Google identity into server-controlled student eligibility.
// The browser cannot reach this outcome on its own: ncku_verified is not
// grantable to the `authenticated` role at all (see 20260823000200_rls.sql),
// and record_student_verification() is granted to service_role only.
//
// All of the decision-making lives in ../_shared/verify-student-handler.js so
// that it can be exercised by tests/edge-function.test.mjs. This file is the
// Deno adapter: real environment, real Supabase client, nothing else.

import { createClient } from '@supabase/supabase-js';
import { createVerifyStudentHandler } from '../_shared/verify-student-handler.js';

const handler = createVerifyStudentHandler({
  env: {
    SUPABASE_URL: Deno.env.get('SUPABASE_URL') ?? '',
    SUPABASE_ANON_KEY: Deno.env.get('SUPABASE_ANON_KEY') ?? '',
    SUPABASE_SERVICE_ROLE_KEY: Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '',
    GOOGLE_CLIENT_ID: Deno.env.get('GOOGLE_CLIENT_ID') ?? '',
    NCKU_HOSTED_DOMAIN: Deno.env.get('NCKU_HOSTED_DOMAIN') ?? 'gs.ncku.edu.tw',
    // Required. With no allowlist the function refuses every request rather
    // than answering with Access-Control-Allow-Origin: *.
    ALLOWED_ORIGINS: Deno.env.get('ALLOWED_ORIGINS') ?? '',
  },
  createClient,
});

Deno.serve(handler);
