// Supabase authentication + authorization lookup.
//
// Authentication answers "who is this". Authorization is answered only by
// reading admin_users / student_profiles under RLS - never by reading
// user_metadata, localStorage or the URL.

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.45.4';
import { config, isConfigured, isGoogleConfigured } from './config.js';
import { codeForError } from './messages.js';

export class AuthError extends Error {
  constructor(code, cause) {
    super(code);
    this.name = 'AuthError';
    this.code = code;
    this.cause = cause;
  }
}

let client;

export function supabase() {
  if (!isConfigured()) throw new AuthError('not_configured');
  client ??= createClient(config.supabaseUrl, config.supabaseAnonKey, {
    auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true, flowType: 'pkce' },
  });
  return client;
}

export async function getSession() {
  try {
    const { data, error } = await supabase().auth.getSession();
    if (error) throw new AuthError(codeForError(error), error);
    return data.session ?? null;
  } catch (error) {
    if (error instanceof AuthError) throw error;
    throw new AuthError(codeForError(error), error);
  }
}

/**
 * Read the caller's authorization rows. RLS means a student's query for
 * admin_users simply returns nothing - there is no privileged read here.
 */
export async function loadAuthorization(userId) {
  const db = supabase();
  // Filtered by user_id on purpose: an owner can read every admin_users row,
  // and an admin every student_profiles row, so "the caller's own record"
  // has to be asked for explicitly rather than inferred from RLS.
  const [adminResult, profileResult] = await Promise.all([
    db
      .from('admin_users')
      .select('user_id, organization, display_name, role, is_active')
      .eq('user_id', userId)
      .maybeSingle(),
    db
      .from('student_profiles')
      .select('user_id, email, department, year, ncku_verified, is_active')
      .eq('user_id', userId)
      .maybeSingle(),
  ]);

  for (const result of [adminResult, profileResult]) {
    // PGRST116 = no rows for maybeSingle, which is a normal answer.
    if (result.error && result.error.code !== 'PGRST116') {
      throw new AuthError(codeForError(result.error), result.error);
    }
  }
  return { admin: adminResult.data ?? null, profile: profileResult.data ?? null };
}

export async function loadAuthState() {
  const session = await getSession();
  if (!session) return { hasSession: false, session: null, admin: null, profile: null };
  const { admin, profile } = await loadAuthorization(session.user.id);
  return { hasSession: true, session, admin, profile };
}

// ---------------------------------------------------------------------
// Google sign-in (students)
// ---------------------------------------------------------------------

let gsiPromise;

function loadGoogleScript() {
  gsiPromise ??= new Promise((resolve, reject) => {
    if (window.google?.accounts?.id) return resolve(window.google);
    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.onload = () => (window.google?.accounts?.id ? resolve(window.google) : reject(new AuthError('google_unavailable')));
    script.onerror = () => reject(new AuthError('google_unavailable'));
    document.head.appendChild(script);
  });
  return gsiPromise;
}

async function makeNonce() {
  const raw = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(raw));
  const hashed = Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
  // Google receives the hash and embeds it in the ID token; Supabase gets the
  // raw value and checks the pair when it mints the session. That check is
  // Supabase's, and it is the only one worth making: our edge function does
  // NOT re-check a nonce, because a value this same client just generated
  // proves nothing to it. Account binding is done by Google `sub` instead.
  return { raw, hashed };
}

/**
 * Render Google's official sign-in button into `container`.
 * `onCredential(idToken, { rawNonce })` fires once the user picks an account.
 */
export async function mountGoogleButton(container, onCredential, onError) {
  if (!isGoogleConfigured()) throw new AuthError('not_configured');
  const google = await loadGoogleScript();
  const { raw, hashed } = await makeNonce();

  google.accounts.id.initialize({
    client_id: config.googleClientId,
    nonce: hashed,
    ux_mode: 'popup',
    callback: (response) => {
      Promise.resolve(onCredential(response.credential, { rawNonce: raw })).catch(onError);
    },
  });

  google.accounts.id.renderButton(container, {
    theme: 'outline',
    size: 'large',
    width: Math.min(container.clientWidth || 320, 400),
    text: 'continue_with',
    shape: 'rectangular',
    locale: 'zh_TW',
  });
}

/**
 * Exchange a Google ID token for a Supabase session, then have the server
 * verify the hosted domain. Signs out and throws if verification fails, so a
 * non-NCKU account never keeps a usable session.
 */
export async function completeGoogleSignIn(credential, { rawNonce }) {
  const db = supabase();

  const { error: signInError } = await db.auth.signInWithIdToken({
    provider: 'google',
    token: credential,
    nonce: rawNonce,
  });
  if (signInError) throw new AuthError(codeForError(signInError), signInError);

  let result;
  try {
    result = await db.functions.invoke('verify-ncku-student', {
      body: { id_token: credential },
    });
  } catch (error) {
    await db.auth.signOut();
    throw new AuthError('network_error', error);
  }

  if (result.error) {
    // FunctionsHttpError keeps the JSON body on `context`.
    let code = 'invalid_token';
    try {
      const body = await result.error.context?.json?.();
      if (body?.error) code = body.error;
    } catch {
      /* keep the default */
    }
    await db.auth.signOut();
    throw new AuthError(code, result.error);
  }

  return result.data?.profile ?? null;
}

// ---------------------------------------------------------------------
// Password sign-in (administrators, and any account given a password)
// ---------------------------------------------------------------------

export async function signInWithPassword(email, password) {
  const { error } = await supabase().auth.signInWithPassword({ email: email.trim(), password });
  if (error) throw new AuthError(codeForError(error), error);
}

export async function requestPasswordReset(email) {
  const redirectTo = new URL('reset-password.html', window.location.href).toString();
  const { error } = await supabase().auth.resetPasswordForEmail(email.trim(), { redirectTo });
  // Errors other than transport problems are swallowed on purpose: the caller
  // always shows the same "if that address exists" message.
  if (error && codeForError(error) === 'network_error') throw new AuthError('network_error', error);
}

export async function updatePassword(password) {
  const { error } = await supabase().auth.updateUser({ password });
  if (error) throw new AuthError(codeForError(error), error);
}

export async function signOut() {
  try {
    await supabase().auth.signOut();
  } catch {
    /* already signed out or offline - nothing useful to tell the user */
  }
}
