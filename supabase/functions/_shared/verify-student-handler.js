// verify-ncku-student, as a plain request handler.
//
// The Deno entrypoint (../verify-ncku-student/index.ts) supplies the real
// environment and the real Supabase client; the Node tests supply fakes. The
// logic that decides who gets verified therefore runs under test, rather than
// only the JWT helper underneath it.
//
// Flow:
//   1. Identify the caller from their Supabase access token. NOTHING in the
//      request body may influence which account is verified.
//   2. Verify the Google ID token against Google's JWKS.
//   3. Require hd === gs.ncku.edu.tw.
//   4. Bind the token to the caller: the Google identity linked to this
//      Supabase user must carry the same `sub`. Without this step a student
//      could verify someone else's account with a borrowed NCKU token.
//   5. record_student_verification() writes the profile and the audit entry in
//      one transaction, as service_role. A failure there is a failed request -
//      never a silent success.

import { IdTokenError, verifyGoogleIdToken } from './verify-google-id-token.js';

const PROFILE_FIELDS = ['user_id', 'email', 'department', 'year', 'ncku_verified', 'is_active'];

/** Short, non-reversible tag for logs. The raw Google subject is stable across
 *  every service the account touches, so it never goes into a log line. */
export async function fingerprint(value) {
  try {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(value)));
    return Array.from(new Uint8Array(digest).slice(0, 4))
      .map((byte) => byte.toString(16).padStart(2, '0'))
      .join('');
  } catch {
    return 'unavailable';
  }
}

export function createVerifyStudentHandler({ env, createClient, verifyIdToken = verifyGoogleIdToken, log = console }) {
  const allowedOrigins = String(env.ALLOWED_ORIGINS ?? '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

  const hostedDomain = env.NCKU_HOSTED_DOMAIN || 'gs.ncku.edu.tw';

  function corsHeaders(origin) {
    // No wildcard fallback: an unconfigured allowlist is a misconfiguration,
    // handled before this is ever called.
    const headers = {
      'Access-Control-Allow-Headers': 'authorization, content-type',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      Vary: 'Origin',
    };
    if (origin && allowedOrigins.includes(origin)) {
      headers['Access-Control-Allow-Origin'] = origin;
    }
    return headers;
  }

  function json(body, status, origin) {
    return new Response(JSON.stringify(body), {
      status,
      headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' },
    });
  }

  return async function handler(req) {
    const origin = req.headers.get('origin');

    // Fail closed on configuration rather than serving every origin.
    if (allowedOrigins.length === 0) {
      log.error('verify-ncku-student is missing ALLOWED_ORIGINS');
      return json({ error: 'server_misconfigured' }, 500, null);
    }
    if (origin && !allowedOrigins.includes(origin)) {
      log.error('verify-ncku-student rejected an origin', { origin });
      return json({ error: 'origin_not_allowed' }, 403, null);
    }

    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders(origin) });
    if (req.method !== 'POST') return json({ error: 'method_not_allowed' }, 405, origin);

    const authHeader = req.headers.get('Authorization') ?? '';
    if (!authHeader.startsWith('Bearer ')) {
      return json({ error: 'unauthenticated' }, 401, origin);
    }

    // 1. Who is calling? Resolved from the JWT by Supabase, not from the body.
    const caller = createClient(env.SUPABASE_URL, env.SUPABASE_ANON_KEY, {
      global: { headers: { Authorization: authHeader } },
      auth: { persistSession: false },
    });
    const { data: userData, error: userError } = await caller.auth.getUser();
    if (userError || !userData?.user?.id) {
      return json({ error: 'unauthenticated' }, 401, origin);
    }
    const userId = userData.user.id;

    let body;
    try {
      body = await req.json();
    } catch {
      return json({ error: 'invalid_request' }, 400, origin);
    }
    if (!body || typeof body !== 'object') {
      return json({ error: 'invalid_request' }, 400, origin);
    }

    // 2-3. Verify the token and enforce the hosted domain.
    let identity;
    try {
      identity = await verifyIdToken(typeof body.id_token === 'string' ? body.id_token : '', {
        clientId: env.GOOGLE_CLIENT_ID ?? '',
        hostedDomain,
      });
    } catch (error) {
      const code = error instanceof IdTokenError ? error.code : 'invalid_token';
      log.error('id token rejected', { userId, code });
      if (code === 'server_misconfigured') return json({ error: 'server_misconfigured' }, 500, origin);
      // Every other failure is one thing to the browser: not an NCKU account.
      return json({ error: code === 'wrong_domain' ? 'wrong_domain' : 'invalid_token' }, 403, origin);
    }

    const admin = createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
      auth: { persistSession: false },
    });

    // 4. Bind the verified Google identity to this Supabase user.
    const { data: adminUser, error: adminUserError } = await admin.auth.admin.getUserById(userId);
    if (adminUserError || !adminUser?.user) {
      return json({ error: 'unauthenticated' }, 401, origin);
    }
    const bound = (adminUser.user.identities ?? []).some(
      (i) => i?.provider === 'google' && (i.provider_id === identity.sub || i.id === identity.sub)
    );
    if (!bound) {
      log.error('identity binding failed', { userId, sub_fp: await fingerprint(identity.sub) });
      return json({ error: 'identity_mismatch' }, 403, origin);
    }

    // 5. One transaction: profile write + audit entry, attributed to the caller.
    const { data: profileRows, error: writeError } = await admin.rpc('record_student_verification', {
      p_user_id: userId,
      p_email: identity.email,
      p_google_sub: identity.sub,
    });

    if (writeError) {
      const alreadyBound = /already bound/i.test(writeError.message ?? '');
      log.error('verification write failed', {
        userId,
        code: writeError.code ?? null,
        alreadyBound,
      });
      return alreadyBound
        ? json({ error: 'identity_mismatch' }, 403, origin)
        : json({ error: 'profile_write_failed' }, 500, origin);
    }

    const profile = Array.isArray(profileRows) ? profileRows[0] : profileRows;
    if (!profile) {
      log.error('verification returned no profile', { userId });
      return json({ error: 'profile_write_failed' }, 500, origin);
    }

    // google_sub never travels back to the browser.
    const safeProfile = Object.fromEntries(PROFILE_FIELDS.map((field) => [field, profile[field] ?? null]));
    return json({ profile: safeProfile }, 200, origin);
  };
}
