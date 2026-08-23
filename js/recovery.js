// Is this page load actually a password-recovery flow?
//
// Pure functions over the landing URL and the Supabase auth event, so the rule
// is unit-testable without a browser. The page uses nothing else to decide.
//
// Why it matters: "there is a session, so show the password box" is not a
// recovery check. Any signed-in account - a student who wandered in, or an
// attacker holding a stolen session - could open reset-password.html and set a
// password, converting a borrowed session into a permanent credential. A
// recovery flow is one that ARRIVED from a recovery link, so that is what we
// look for, and a plain session is not it.

export const RECOVERY = {
  /** The recovery link is still being exchanged for a session. */
  AWAITING: 'awaiting_recovery',
  /** Genuine recovery session - show the form. */
  ALLOWED: 'allowed',
  /** Someone opened the page directly. Never show the form. */
  NOT_RECOVERY: 'reset_not_recovery',
  /** The link was a recovery link, but it is expired, used or malformed. */
  INVALID: 'reset_link_invalid',
};

/**
 * Read the markers Supabase puts on a recovery landing URL, before the client
 * consumes and strips them.
 *
 *   implicit flow -> #access_token=...&type=recovery
 *   PKCE flow     -> ?code=...
 *   email link    -> ?token_hash=...&type=recovery
 *   failure       -> ?error=...&error_code=... (or the same in the hash)
 *
 * @param {string} href
 */
export function readRecoveryMarkers(href) {
  let url;
  try {
    url = new URL(href);
  } catch {
    return { isRecoveryLink: false, hasError: false, errorCode: null };
  }

  const query = url.searchParams;
  const hash = new URLSearchParams(url.hash.startsWith('#') ? url.hash.slice(1) : url.hash);
  const get = (key) => query.get(key) ?? hash.get(key);

  const hasError = Boolean(get('error') || get('error_code') || get('error_description'));
  const type = get('type');

  const isRecoveryLink =
    type === 'recovery' ||
    Boolean(get('code')) ||
    Boolean(get('token_hash')) ||
    Boolean(get('access_token'));

  return { isRecoveryLink, hasError, errorCode: get('error_code') ?? get('error') ?? null };
}

/**
 * @param {object} input
 * @param {{isRecoveryLink: boolean, hasError: boolean}} input.markers
 * @param {string|null} [input.event]       latest Supabase auth event
 * @param {boolean} [input.hasSession]      is there a session right now
 * @param {boolean} [input.timedOut]        did the exchange window elapse
 * @returns {{state: string, showForm: boolean}}
 */
export function classifyRecoveryEntry({ markers, event = null, hasSession = false, timedOut = false }) {
  if (markers.hasError) return deny(RECOVERY.INVALID);

  // The decisive test. No recovery marker on the URL means this page was
  // opened directly, and an existing session does not turn that into a
  // recovery flow.
  if (!markers.isRecoveryLink) return deny(RECOVERY.NOT_RECOVERY);

  if (event === 'PASSWORD_RECOVERY') return { state: RECOVERY.ALLOWED, showForm: true };
  if (hasSession) return { state: RECOVERY.ALLOWED, showForm: true };
  if (timedOut) return deny(RECOVERY.INVALID);
  return deny(RECOVERY.AWAITING);
}

function deny(state) {
  return { state, showForm: false };
}
