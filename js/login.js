// Login page controller.

import {
  AuthError,
  loadAuthState,
  provisionGoogleStudent,
  requestPasswordReset,
  signInWithGoogle,
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
let googleLoginButton;

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
  if (googleLoginButton) googleLoginButton.disabled = busy;
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

async function startGoogleSignIn() {
  clearStatus();
  setBusy(true);
  try {
    await signInWithGoogle();
  } catch (error) {
    handleError(error);
  }
}

function mountGoogleLoginButton() {
  googleSlot.replaceChildren();
  googleLoginButton = document.createElement('button');
  googleLoginButton.type = 'button';
  googleLoginButton.className = 'primary-button google-oauth-button';
  googleLoginButton.textContent = '使用成大 Google 帳號登入';
  googleLoginButton.addEventListener('click', startGoogleSignIn);
  googleSlot.append(googleLoginButton);
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

  try {
    let state = await loadAuthState();
    if (state.hasSession && !state.admin && !state.profile) {
      await provisionGoogleStudent();
      state = await loadAuthState();
    }
    if (state.hasSession) {
      setBusy(true);
      await routeFrom(state);
      return;
    }
  } catch {
    await signOut();
  }

  if (!isGoogleConfigured()) {
    googleFallback.hidden = false;
    googleFallback.textContent = messageFor('not_configured');
    setBusy(false);
    return;
  }

  mountGoogleLoginButton();
  setBusy(false);
}

boot();
