// Public configuration. Everything here is safe to ship to the browser.
//
// NEVER add the Supabase service role key, the Google OAuth client secret,
// or any signing key to this file - see docs/SETUP.md.
//
// Values can be overridden at deploy time by defining window.NCKU_CONFIG
// before this module loads (e.g. a Netlify snippet injection).

const overrides = typeof window !== 'undefined' ? window.NCKU_CONFIG ?? {} : {};

export const config = {
  supabaseUrl: overrides.supabaseUrl ?? 'https://YOUR-PROJECT-REF.supabase.co',
  supabaseAnonKey: overrides.supabaseAnonKey ?? 'YOUR-SUPABASE-PUBLISHABLE-ANON-KEY',
  googleClientId: overrides.googleClientId ?? 'YOUR-GOOGLE-OAUTH-CLIENT-ID.apps.googleusercontent.com',
  hostedDomain: overrides.hostedDomain ?? 'gs.ncku.edu.tw',
};

export function isConfigured() {
  return !config.supabaseUrl.includes('YOUR-PROJECT-REF') && !config.supabaseAnonKey.startsWith('YOUR-');
}

export function isGoogleConfigured() {
  return !config.googleClientId.startsWith('YOUR-');
}
