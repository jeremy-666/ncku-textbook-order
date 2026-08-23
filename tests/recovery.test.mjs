// When may the password-reset form appear?
// Pure functions, no browser - see js/recovery.js.

import test from 'node:test';
import assert from 'node:assert/strict';
import { RECOVERY, classifyRecoveryEntry, readRecoveryMarkers } from '../js/recovery.js';

const PAGE = 'https://forms.example.test/reset-password.html';
const at = (suffix = '') => readRecoveryMarkers(`${PAGE}${suffix}`);

const verdictFor = (suffix, extra = {}) => classifyRecoveryEntry({ markers: at(suffix), ...extra });

test('a normal authenticated session cannot open the reset form', () => {
  // The exact finding: any signed-in account could previously walk in and set
  // a password. No recovery marker on the URL means no form, session or not.
  for (const extra of [
    { hasSession: true },
    { hasSession: true, event: 'SIGNED_IN' },
    { hasSession: true, event: 'INITIAL_SESSION' },
    { hasSession: true, event: 'TOKEN_REFRESHED' },
  ]) {
    const verdict = verdictFor('', extra);
    assert.equal(verdict.showForm, false);
    assert.equal(verdict.state, RECOVERY.NOT_RECOVERY);
  }
});

test('a signed-out visitor opening the page directly is told the same thing', () => {
  const verdict = verdictFor('');
  assert.equal(verdict.showForm, false);
  assert.equal(verdict.state, RECOVERY.NOT_RECOVERY);
});

test('an implicit-flow recovery link is allowed', () => {
  const suffix = '#access_token=abc.def.ghi&expires_in=3600&refresh_token=r&token_type=bearer&type=recovery';
  assert.equal(at(suffix).isRecoveryLink, true);

  const recovering = verdictFor(suffix, { event: 'PASSWORD_RECOVERY', hasSession: true });
  assert.equal(recovering.showForm, true);
  assert.equal(recovering.state, RECOVERY.ALLOWED);
});

test('a PKCE recovery link is allowed once the code is exchanged', () => {
  const suffix = '?code=8b0f3a2e-code';
  assert.equal(at(suffix).isRecoveryLink, true);

  const waiting = verdictFor(suffix);
  assert.equal(waiting.showForm, false);
  assert.equal(waiting.state, RECOVERY.AWAITING, 'no form while the exchange is in flight');

  const exchanged = verdictFor(suffix, { hasSession: true, event: 'SIGNED_IN' });
  assert.equal(exchanged.showForm, true);
});

test('a verification-link recovery is recognised', () => {
  assert.equal(at('?token_hash=pkce_abc&type=recovery').isRecoveryLink, true);
  assert.equal(verdictFor('?token_hash=pkce_abc&type=recovery', { hasSession: true }).showForm, true);
});

test('an expired or already-used link is refused safely', () => {
  const expired = '?error=access_denied&error_code=otp_expired&error_description=Email+link+is+invalid+or+has+expired';
  assert.equal(at(expired).hasError, true);

  const verdict = verdictFor(expired, { hasSession: true, event: 'PASSWORD_RECOVERY' });
  assert.equal(verdict.showForm, false, 'an error on the URL wins over everything else');
  assert.equal(verdict.state, RECOVERY.INVALID);

  // Supabase reports the same failure in the hash on the implicit flow.
  assert.equal(at('#error=access_denied&error_code=otp_expired').hasError, true);
});

test('a recovery link that never produces a session ends as invalid', () => {
  const verdict = verdictFor('?code=never-exchanged', { timedOut: true });
  assert.equal(verdict.showForm, false);
  assert.equal(verdict.state, RECOVERY.INVALID);
});

test('a malformed URL is not a recovery flow', () => {
  const markers = readRecoveryMarkers('not-a-url');
  assert.equal(markers.isRecoveryLink, false);
  assert.equal(classifyRecoveryEntry({ markers, hasSession: true }).showForm, false);
});

test('type=signup or type=magiclink is not a password recovery', () => {
  // These carry a session too, and are exactly the confusion to avoid: only
  // an explicit recovery marker opens the form.
  const verdict = classifyRecoveryEntry({
    markers: { isRecoveryLink: false, hasError: false, errorCode: null },
    event: 'SIGNED_IN',
    hasSession: true,
  });
  assert.equal(verdict.state, RECOVERY.NOT_RECOVERY);
});
