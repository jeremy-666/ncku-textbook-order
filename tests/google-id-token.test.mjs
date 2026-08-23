// The NCKU eligibility decision, tested against real signatures.
//
// A local RSA key pair stands in for Google's. Every rejection case below is
// a token an attacker could realistically present.

import test from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair } from 'jose';
import { verifyGoogleIdToken } from '../supabase/functions/_shared/verify-google-id-token.js';

const CLIENT_ID = 'test-client.apps.googleusercontent.com';
const OTHER_CLIENT_ID = 'someone-elses-client.apps.googleusercontent.com';
const KID = 'google-test-key';

const google = await generateKeyPair('RS256');
const impostor = await generateKeyPair('RS256');

const publicJwk = { ...(await exportJWK(google.publicKey)), kid: KID, alg: 'RS256', use: 'sig' };
const jwks = createLocalJWKSet({ keys: [publicJwk] });

const BASE = { email: 'student@gs.ncku.edu.tw', email_verified: true, hd: 'gs.ncku.edu.tw' };
const nowSec = () => Math.floor(Date.now() / 1000);

async function token(claims = {}, options = {}) {
  const {
    key = google.privateKey,
    kid = KID,
    alg = 'RS256',
    issuer = 'https://accounts.google.com',
    audience = CLIENT_ID,
    expires = '5m',
    issuedAt = nowSec(),
  } = options;

  const payload = { ...BASE, ...claims };
  delete payload.sub;

  let jwt = new SignJWT(payload).setProtectedHeader({ alg, kid }).setIssuer(issuer).setAudience(audience);
  if (claims.sub !== null) jwt = jwt.setSubject(claims.sub ?? '109000000000000000001');
  if (issuedAt !== null) jwt = jwt.setIssuedAt(issuedAt);
  if (expires !== null) jwt = jwt.setExpirationTime(expires);
  return jwt.sign(key);
}

const verify = (jwt, extra = {}) => verifyGoogleIdToken(jwt, { clientId: CLIENT_ID, jwks, ...extra });

async function rejects(jwt, code, extra) {
  await assert.rejects(
    () => verify(jwt, extra),
    (error) => {
      assert.equal(error.name, 'IdTokenError');
      assert.equal(error.code, code, `expected code "${code}", got "${error.code}"`);
      return true;
    }
  );
}

test('a valid gs.ncku.edu.tw token is accepted', async () => {
  const identity = await verify(await token());
  assert.equal(identity.hd, 'gs.ncku.edu.tw');
  assert.equal(identity.email, 'student@gs.ncku.edu.tw');
  assert.equal(identity.sub, '109000000000000000001');
});

test('an NCKU-looking email with no hd claim is rejected', async () => {
  // The whole point: email suffix alone must never authorize anyone.
  await rejects(await token({ hd: undefined, email: 'student@gs.ncku.edu.tw' }), 'wrong_domain');
});

test('a different workspace domain is rejected', async () => {
  await rejects(await token({ hd: 'ncku.edu.tw', email: 'staff@ncku.edu.tw' }), 'wrong_domain');
  await rejects(await token({ hd: 'gs.ncku.edu.tw.evil.com' }), 'wrong_domain');
  await rejects(await token({ hd: 'GS.NCKU.EDU.TW' }), 'wrong_domain');
});

test('a personal gmail account is rejected', async () => {
  await rejects(await token({ hd: undefined, email: 'someone@gmail.com' }), 'wrong_domain');
});

test('a token signed by anybody but Google is rejected', async () => {
  // The forged token carries perfect claims - only the signature is wrong.
  await rejects(await token({}, { key: impostor.privateKey }), 'invalid_signature');
});

test('an unsupported algorithm is rejected before any key is consulted', async () => {
  const symmetric = new TextEncoder().encode('0123456789abcdef0123456789abcdef');
  const hs256 = await new SignJWT(BASE)
    .setProtectedHeader({ alg: 'HS256', kid: KID })
    .setIssuer('https://accounts.google.com')
    .setAudience(CLIENT_ID)
    .setSubject('109000000000000000001')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(symmetric);
  await rejects(hs256, 'invalid_algorithm');
});

test('a token minted for another OAuth client is rejected', async () => {
  await rejects(await token({}, { audience: OTHER_CLIENT_ID }), 'invalid_audience');
});

test('a multi-audience token is only accepted with a matching azp', async () => {
  // jose alone would accept an aud array that merely contains our client id -
  // a token issued to somebody else that happens to name us.
  await rejects(await token({}, { audience: [CLIENT_ID, OTHER_CLIENT_ID] }), 'invalid_audience');

  await rejects(
    await token({ azp: OTHER_CLIENT_ID }, { audience: [CLIENT_ID, OTHER_CLIENT_ID] }),
    'invalid_audience'
  );

  const identity = await verify(await token({ azp: CLIENT_ID }, { audience: [CLIENT_ID, OTHER_CLIENT_ID] }));
  assert.equal(identity.sub, '109000000000000000001');
});

test('an azp naming another client is rejected even with a single audience', async () => {
  await rejects(await token({ azp: OTHER_CLIENT_ID }), 'invalid_audience');
});

test('a token from another issuer is rejected', async () => {
  await rejects(await token({}, { issuer: 'https://accounts.evil.example' }), 'invalid_issuer');
});

test('an expired token is rejected', async () => {
  await rejects(await token({}, { expires: '-10m' }), 'token_expired');
});

test('a token with no exp is rejected rather than treated as eternal', async () => {
  await rejects(await token({}, { expires: null }), 'missing_claim');
});

test('a token with no iat is rejected', async () => {
  await rejects(await token({}, { issuedAt: null }), 'missing_claim');
});

test('a token issued too long ago is rejected even if it has not expired', async () => {
  // Google ID tokens live an hour; this one is still signed and unexpired,
  // but it is not the sign-in happening right now.
  const stale = await token({}, { issuedAt: nowSec() - 1800, expires: '2h' });
  await rejects(stale, 'token_too_old');

  // ...and the window is configurable for anyone who needs a different one.
  const identity = await verify(stale, { maxTokenAgeSec: 3600 });
  assert.equal(identity.hd, 'gs.ncku.edu.tw');
});

test('a token issued in the future is rejected', async () => {
  await rejects(await token({}, { issuedAt: nowSec() + 1800, expires: '2h' }), 'invalid_issued_at');
});

test('garbage is rejected without touching the key set', async () => {
  await rejects('not-a-jwt', 'invalid_token');
  await rejects('', 'invalid_token');
  await rejects(undefined, 'invalid_token');
});

test('an unverified Google email is rejected', async () => {
  await rejects(await token({ email_verified: false }), 'email_unverified');
});

test('the nonce claim carries no authority', async () => {
  // V1 has no server-issued nonce store, so the verifier does not pretend to
  // do replay protection. Account binding is the edge function's job: the
  // Google sub must already be linked to the Supabase user being verified.
  const identity = await verify(await token({ nonce: 'anything-at-all' }));
  assert.equal(identity.sub, '109000000000000000001');
});

test('a missing client id fails closed', async () => {
  const jwt = await token();
  await assert.rejects(
    () => verifyGoogleIdToken(jwt, { clientId: '', jwks }),
    (error) => error.code === 'server_misconfigured'
  );
});

test('the hosted domain is configurable but still mandatory', async () => {
  const identity = await verify(await token({ hd: 'example.edu' }), { hostedDomain: 'example.edu' });
  assert.equal(identity.hd, 'example.edu');
  await rejects(await token({ hd: 'gs.ncku.edu.tw' }), 'wrong_domain', { hostedDomain: 'example.edu' });
});
