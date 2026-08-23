// Login page controller.

import {
  AuthError,
  completeGoogleSignIn,
  loadAuthState,
  mountGoogleButton,
  requestPasswordReset,
  signInWithPassword,
  signOut,
} from './auth.js';
import { ROUTES, resolveDestination } from './routing.js';
import { codeForError, messageFor } from './messages.js';
import { isConfigured, isGoogleConfigured } from './config.js';

const banner = document.querySelector('#statusBanner');
const loader = document.querySelector('#pageLoader');
const passwordForm = document.querySelector('#passwordForm');
const loginButton = document.querySelector('#loginButton');
const emailInput = document.querySelector('#email');
const passwordInput = document.querySelector('#password');
const forgotButton = document.querySelector('#forgotPassword');
const googleSlot = document.querySelector('#googleButton');
const googleFallback = document.querySelector('#googleFallback');

function showStatus(code, tone = 'error') {
  banner.textContent = messageFor(code);
  banner.dataset.tone = tone;
  banner.hidden = false;
}

function clearStatus() {
  banner.hidden = true;
  banner.textContent = '';
}

function setBusy(busy) {
  loader.hidden = !busy;
  loader.toggleAttribute('data-active', busy);
  loginButton.disabled = busy;
  forgotButton.disabled = busy;
  loginButton.textContent = busy ? '登入中…' : '登入';
}

/** Send an authenticated user onward, or deny with a message. */
async function routeFrom(state) {
  const { route, reason } = resolveDestination(state);
  if (route === null || route === ROUTES.LOGIN) {
    await signOut();
    showStatus(reason);
    setBusy(false);
    return;
  }
  window.location.replace(route);
}

function handleError(error) {
  const code = error instanceof AuthError ? error.code : codeForError(error);
  showStatus(code);
  setBusy(false);
}

// --- Google -----------------------------------------------------------

async function onGoogleCredential(credential, nonce) {
  clearStatus();
  setBusy(true);
  try {
    await completeGoogleSignIn(credential, nonce);
    await routeFrom(await loadAuthState());
  } catch (error) {
    handleError(error);
  }
}

// --- Password ---------------------------------------------------------

passwordForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearStatus();

  const email = emailInput.value.trim();
  const password = passwordInput.value;
  if (!email || !password) {
    showStatus('invalid_credentials');
    return;
  }

  setBusy(true);
  try {
    await signInWithPassword(email, password);
    // Authenticating is not authorization: routeFrom re-reads admin_users /
    // student_profiles and signs the user back out if neither qualifies.
    await routeFrom(await loadAuthState());
  } catch (error) {
    handleError(error);
  }
});

forgotButton.addEventListener('click', async () => {
  clearStatus();
  const email = emailInput.value.trim();
  if (!email) {
    emailInput.focus();
    showStatus('invalid_credentials');
    return;
  }
  setBusy(true);
  try {
    await requestPasswordReset(email);
  } catch (error) {
    handleError(error);
    return;
  }
  // Identical response whether or not the address exists.
  setBusy(false);
  showStatus('reset_sent', 'info');
});

// --- Boot -------------------------------------------------------------

async function boot() {
  const reason = new URLSearchParams(window.location.search).get('reason');
  if (reason) {
    showStatus(reason);
    history.replaceState(null, '', window.location.pathname);
  }

  if (!isConfigured()) {
    showStatus('not_configured');
    setBusy(false);
    googleFallback.hidden = false;
    googleFallback.textContent = messageFor('not_configured');
    return;
  }

  // Already signed in? Skip the form.
  try {
    const state = await loadAuthState();
    if (state.hasSession) {
      setBusy(true);
      await routeFrom(state);
    }
  } catch {
    await signOut();
  }

  if (!isGoogleConfigured()) {
    googleFallback.hidden = false;
    googleFallback.textContent = messageFor('not_configured');
    return;
  }

  try {
    await mountGoogleButton(googleSlot, onGoogleCredential, handleError);
  } catch (error) {
    googleFallback.hidden = false;
    googleFallback.textContent = messageFor(error instanceof AuthError ? error.code : 'google_unavailable');
  }
}

setBusy(false);
boot();
