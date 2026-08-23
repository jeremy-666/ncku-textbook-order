// Page guard.
//
// Run before a protected page renders anything. This is a usability layer:
// it keeps people out of pages they cannot use and gives them a readable
// reason. It is NOT the security boundary - a user who deletes this script
// still gets zero rows back from every query, because RLS decides.

import { AuthError, loadAuthState, signOut, supabase } from './auth.js';
import { ROUTES, canAccessPage } from './routing.js';
import { codeForError } from './messages.js';

function redirect(target, reason) {
  const url = new URL(target, window.location.href);
  if (reason) url.searchParams.set('reason', reason);
  window.location.replace(url.toString());
}

/**
 * @param {'admin'|'student'|'onboarding'} requirement
 * @returns {Promise<{session: object, admin: object|null, profile: object|null}>}
 *          resolves only if access is allowed; otherwise it navigates away
 *          and never resolves.
 */
export async function protectPage(requirement) {
  document.documentElement.dataset.authState = 'checking';

  let state;
  try {
    state = await loadAuthState();
  } catch (error) {
    const code = error instanceof AuthError ? error.code : codeForError(error);
    await signOut();
    redirect(ROUTES.LOGIN, code);
    return new Promise(() => {});
  }

  const verdict = canAccessPage(requirement, state);
  if (!verdict.allowed) {
    // Denied outright (no authorization record, suspended, disabled admin):
    // drop the session so a stale token cannot be reused.
    if (verdict.redirectTo === ROUTES.LOGIN) await signOut();
    redirect(verdict.redirectTo, verdict.redirectTo === ROUTES.LOGIN ? verdict.reason : undefined);
    return new Promise(() => {});
  }

  // If the session ends while the page is open, leave immediately.
  supabase().auth.onAuthStateChange((event) => {
    if (event === 'SIGNED_OUT') redirect(ROUTES.LOGIN, 'session_expired');
  });

  document.documentElement.dataset.authState = 'ready';
  return state;
}

/** Wire any [data-signout] element to sign out and return to the login page. */
export function wireSignOut() {
  document.querySelectorAll('[data-signout]').forEach((element) => {
    element.addEventListener('click', async (event) => {
      event.preventDefault();
      await signOut();
      redirect(ROUTES.LOGIN);
    });
  });
}
