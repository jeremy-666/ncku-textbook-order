// Password reset landing page.
//
// The form appears only for a genuine password-recovery flow - see
// js/recovery.js for the rule and why "any session will do" is not one.
// The landing URL is read at module load, before the Supabase client consumes
// and strips the recovery parameters.

import { AuthError, signOut, supabase, updatePassword } from './auth.js';
import { RECOVERY, classifyRecoveryEntry, readRecoveryMarkers } from './recovery.js';
import { codeForError, messageFor } from './messages.js';
import { isConfigured } from './config.js';

const MARKERS = readRecoveryMarkers(window.location.href);
const EXCHANGE_TIMEOUT_MS = 4000;

const banner = document.querySelector('#statusBanner');
const form = document.querySelector('#resetForm');
const passwordInput = document.querySelector('#password');
const confirmInput = document.querySelector('#confirm');
const resetButton = document.querySelector('#resetButton');

function show(code, tone = 'error') {
  banner.textContent = messageFor(code);
  banner.dataset.tone = tone;
  banner.hidden = false;
}

function apply(verdict) {
  if (verdict.showForm) {
    banner.hidden = true;
    form.hidden = false;
    return true;
  }
  form.hidden = true;
  if (verdict.state !== RECOVERY.AWAITING) show(verdict.state);
  return false;
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  banner.hidden = true;

  if (passwordInput.value.length < 8) return show('password_too_short');
  if (passwordInput.value !== confirmInput.value) return show('password_mismatch');

  resetButton.disabled = true;
  resetButton.textContent = '更新中…';
  try {
    await updatePassword(passwordInput.value);
    form.hidden = true;
    show('password_updated', 'success');
    // The recovery session is single-purpose; make them log in properly.
    await signOut();
    setTimeout(() => window.location.replace('index.html'), 2500);
  } catch (error) {
    show(error instanceof AuthError ? error.code : codeForError(error));
    resetButton.disabled = false;
    resetButton.textContent = '更新密碼';
  }
});

async function boot() {
  if (!isConfigured()) return show('not_configured');

  // Decided before any client exists: a page opened directly never gets the
  // form, however many valid sessions the browser is holding.
  const initial = classifyRecoveryEntry({ markers: MARKERS });
  if (initial.state === RECOVERY.NOT_RECOVERY || initial.state === RECOVERY.INVALID) {
    apply(initial);
    return;
  }

  const db = supabase();

  // The recovery session may still be mid-exchange when this runs.
  const { data } = await db.auth.getSession();
  if (apply(classifyRecoveryEntry({ markers: MARKERS, hasSession: Boolean(data.session) }))) return;

  const stop = setTimeout(() => {
    subscription?.unsubscribe();
    apply(classifyRecoveryEntry({ markers: MARKERS, timedOut: true }));
  }, EXCHANGE_TIMEOUT_MS);

  const {
    data: { subscription },
  } = db.auth.onAuthStateChange((event, session) => {
    const verdict = classifyRecoveryEntry({ markers: MARKERS, event, hasSession: Boolean(session) });
    if (verdict.showForm) {
      clearTimeout(stop);
      subscription.unsubscribe();
      apply(verdict);
    }
  });
}

boot();
