import { AuthError, loadAuthState, signInWithGoogle, signOut, supabase } from './auth.js';
import { ROUTES, resolveDestination } from './routing.js';
import { codeForError, messageFor } from './messages.js';
import { isConfigured, isGoogleConfigured } from './config.js';

const banner = document.querySelector('#statusBanner');
const loader = document.querySelector('#pageLoader');
const passwordForm = document.querySelector('#passwordForm');
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

async function routeFrom(state) {
  const { route, reason } = resolveDestination(state);
  if (!route || route === ROUTES.LOGIN) {
    await signOut();
    showStatus(reason);
    setBusy(false);
    return;
  }
  window.location.replace(route);
}

function handleError(error) {
  showStatus(error instanceof AuthError ? error.code : codeForError(error));
  setBusy(false);
}

async function enterAfterGoogle() {
  try {
    await routeFrom(await loadAuthState());
  } catch (error) {
    handleError(error);
  }
}

async function startGoogleSignIn() {
  banner.hidden = true;
  setBusy(true);
  try {
    await signInWithGoogle();
  } catch (error) {
    handleError(error);
  }
}

function mountGoogleButton() {
  googleSlot.replaceChildren();
  googleButton = document.createElement('button');
  googleButton.type = 'button';
  googleButton.className = 'primary-button google-oauth-button';
  googleButton.textContent = '使用成大 Google 帳號登入';
  googleButton.addEventListener('click', startGoogleSignIn);
  googleSlot.append(googleButton);
}

async function boot() {
  passwordForm.hidden = true;
  passwordForm.previousElementSibling?.toggleAttribute('hidden', true);

  if (!isConfigured() || !isGoogleConfigured()) {
    showStatus('not_configured');
    googleFallback.hidden = false;
    googleFallback.textContent = messageFor('not_configured');
    return;
  }

  supabase().auth.onAuthStateChange((event, session) => {
    if (event === 'SIGNED_IN' && session) {
      setTimeout(() => { void enterAfterGoogle(); }, 0);
    }
  });

  const state = await loadAuthState();
  if (state.hasSession) {
    await routeFrom(state);
    return;
  }

  mountGoogleButton();
  setBusy(false);
}

boot().catch(handleError);
