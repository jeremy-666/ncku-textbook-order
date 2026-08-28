import { AuthError, loadAuthState, signInWithGoogle, supabase } from './auth.js';
import { ROUTES, resolveDestination } from './routing.js';
import { codeForError, messageFor } from './messages.js';
import { isConfigured, isGoogleConfigured } from './config.js';

const banner = document.querySelector('#statusBanner');
const loader = document.querySelector('#pageLoader');
const googleSlot = document.querySelector('#googleButton');
const googleFallback = document.querySelector('#googleFallback');

let googleButton;

function showStatus(code, tone = 'error') {
  banner.textContent = messageFor(code);
  banner.dataset.tone = tone;
  banner.hidden = false;
}

function setBusy(busy) {
  loader.hidden = !busy;
  loader.toggleAttribute('data-active', busy);
  if (googleButton) googleButton.disabled = busy;
}

function clearCallbackCode() {
  const url = new URL(window.location.href);
  if (!url.searchParams.has('code')) return;
  url.searchParams.delete('code');
  window.history.replaceState({}, '', url);
}

async function continueAfterSignIn() {
  try {
    const state = await loadAuthState();
    if (!state.hasSession) {
      setBusy(false);
      return;
    }

    const { route, reason } = resolveDestination(state);
    if (!route || route === ROUTES.LOGIN) {
      showStatus(reason);
      setBusy(false);
      return;
    }

    clearCallbackCode();
    window.location.replace(route);
  } catch (error) {
    showStatus(error instanceof AuthError ? error.code : codeForError(error));
    setBusy(false);
  }
}

async function startGoogleSignIn() {
  banner.hidden = true;
  setBusy(true);

  try {
    await signInWithGoogle();
  } catch (error) {
    showStatus(error instanceof AuthError ? error.code : codeForError(error));
    setBusy(false);
  }
}

function mountGoogleButton() {
  googleSlot.replaceChildren();

  googleButton = document.createElement('button');
  googleButton.type = 'button';
  googleButton.className = 'primary-button google-login-button';
  googleButton.textContent = '使用成大 Google 帳號登入';
  googleButton.addEventListener('click', startGoogleSignIn);
  googleSlot.appendChild(googleButton);

  googleFallback.hidden = true;
}

async function boot() {
  if (!isConfigured() || !isGoogleConfigured()) {
    showStatus('not_configured');
    return;
  }

  mountGoogleButton();
  setBusy(true);

  supabase().auth.onAuthStateChange((event, session) => {
    if (event === 'SIGNED_IN' && session) {
      window.setTimeout(continueAfterSignIn, 0);
    }
  });

  await continueAfterSignIn();
}

boot();
import { AuthError, loadAuthState, signInWithGoogle, supabase } from './auth.js';
import { ROUTES, resolveDestination } from './routing.js';
import { codeForError, messageFor } from './messages.js';
import { isConfigured, isGoogleConfigured } from './config.js';

const banner = document.querySelector('#statusBanner');
const loader = document.querySelector('#pageLoader');
const googleSlot = document.querySelector('#googleButton');
const googleFallback = document.querySelector('#googleFallback');

let googleButton;

function showStatus(code, tone = 'error') {
  banner.textContent = messageFor(code);
  banner.dataset.tone = tone;
  banner.hidden = false;
}

function setBusy(busy) {
  loader.hidden = !busy;
  loader.toggleAttribute('data-active', busy);
  if (googleButton) googleButton.disabled = busy;
}

function clearCallbackCode() {
  const url = new URL(window.location.href);
  if (!url.searchParams.has('code')) return;
  url.searchParams.delete('code');
  window.history.replaceState({}, '', url);
}

async function continueAfterSignIn() {
  try {
    const state = await loadAuthState();
    if (!state.hasSession) {
      setBusy(false);
      return;
    }

    const { route, reason } = resolveDestination(state);
    if (!route || route === ROUTES.LOGIN) {
      showStatus(reason);
      setBusy(false);
      return;
    }

    clearCallbackCode();
    window.location.replace(route);
  } catch (error) {
    showStatus(error instanceof AuthError ? error.code : codeForError(error));
    setBusy(false);
  }
}

async function startGoogleSignIn() {
  banner.hidden = true;
  setBusy(true);

  try {
    await signInWithGoogle();
  } catch (error) {
    showStatus(error instanceof AuthError ? error.code : codeForError(error));
    setBusy(false);
  }
}

function mountGoogleButton() {
  googleSlot.replaceChildren();

  googleButton = document.createElement('button');
  googleButton.type = 'button';
  googleButton.className = 'primary-button google-login-button';
  googleButton.textContent = '使用成大 Google 帳號登入';
  googleButton.addEventListener('click', startGoogleSignIn);
  googleSlot.appendChild(googleButton);

  googleFallback.hidden = true;
}

async function boot() {
  if (!isConfigured() || !isGoogleConfigured()) {
    showStatus('not_configured');
    return;
  }

  mountGoogleButton();
  setBusy(true);

  supabase().auth.onAuthStateChange((event, session) => {
    if (event === 'SIGNED_IN' && session) {
      window.setTimeout(continueAfterSignIn, 0);
    }
  });

  await continueAfterSignIn();
}

boot();

// Keep only the Google sign-in flow.
