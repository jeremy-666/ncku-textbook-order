// Public configuration. Everything here is safe to ship to the browser.
// Never add the Supabase secret key or the Google OAuth client secret here.
const overrides = typeof window !== 'undefined' ? window.NCKU_CONFIG ?? {} : {};

export const config = {
  supabaseUrl: overrides.supabaseUrl ?? 'https://xsldgufykokfntxqebtj.supabase.co',
  supabaseAnonKey: overrides.supabaseAnonKey ?? 'sb_publishable_ltaNA7nnVozoSCOcZIjg',
  googleClientId: overrides.googleClientId ?? '1009131009421-b7mdojk6ngtnnpltorr8gafr0o3d6tq0.apps.googleusercontent.com',
  hostedDomain: overrides.hostedDomain ?? 'gs.ncku.edu.tw',
};

export function isConfigured() {
  return !config.supabaseUrl.includes('YOUR-PROJECT-REF') && !config.supabaseAnonKey.startsWith('YOUR-');
}

export function isGoogleConfigured() {
  return !config.googleClientId.startsWith('YOUR-');
}
