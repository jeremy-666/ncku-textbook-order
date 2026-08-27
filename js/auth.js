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
    auth: {
      persistSession: true,
      autoRefreshToken: true,
      detectSessionInUrl: true,
      flowType: 'pkce',
    },
  });

  return client;
}

export async function getSession() {
  const { data, error } = await supabase().auth.getSession();
  if (error) throw new AuthError(codeForError(error), error);
  return data.session ?? null;
}

export async function loadAuthorization(userId) {
  const db = supabase();
  const [adminResult, profileResult] = await Promise.all([
    db.from('admin_users')
      .select('user_id, organization, display_name, role, is_active')
      .eq('user_id', userId)
      .maybeSingle(),
    db.from('student_profiles')
      .select('user_id, email, department, year, ncku_verified, is_active')
      .eq('user_id', userId)
      .maybeSingle(),
  ]);

  for (const result of [adminResult, profileResult]) {
    if (result.error && result.error.code !== 'PGRST116') {
      throw new AuthError(codeForError(result.error), result.error);
    }
  }

  return {
    admin: adminResult.data ?? null,
    profile: profileResult.data ?? null,
  };
}

function isNckuGoogleSession(session) {
  const email = String(session?.user?.email ?? '').trim().toLowerCase();
  const domain = String(config.hostedDomain ?? '').trim().toLowerCase();
  const provider = String(session?.user?.app_metadata?.provider ?? '').toLowerCase();
  return provider === 'google' && domain && email.endsWith('@' + domain);
}

export async function loadAuthState() {
  const session = await getSession();

  if (!session) {
    return { hasSession: false, session: null, admin: null, profile: null };
  }

  if (!isNckuGoogleSession(session)) {
    await signOut();
    throw new AuthError('not_verified');
  }

  const { admin, profile } = await loadAuthorization(session.user.id);
  return { hasSession: true, session, admin, profile };
}

export async function signInWithGoogle() {
  if (!isGoogleConfigured()) throw new AuthError('not_configured');

  const { error } = await supabase().auth.signInWithOAuth({
    provider: 'google',
    options: {
      redirectTo: window.location.origin + window.location.pathname,
      queryParams: {
        hd: config.hostedDomain,
        prompt: 'select_account',
      },
    },
  });

  if (error) throw new AuthError(codeForError(error), error);
}

export async function signOut() {
  try {
    await supabase().auth.signOut();
  } catch {
    // A missing or already-ended session does not need another error screen.
  }
}
