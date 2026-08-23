// The verify-ncku-student edge function, exercised as a request handler.
//
// The JWT helper has its own suite; this one is about the decision the
// function makes AROUND it - which account gets verified, and on whose say-so.
// The Supabase clients are fakes, so every assertion here is about our logic
// rather than about the SDK.

import { beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createVerifyStudentHandler } from '../supabase/functions/_shared/verify-student-handler.js';
import { IdTokenError } from '../supabase/functions/_shared/verify-google-id-token.js';

const ORIGIN = 'https://forms.example.test';
const CALLER_ID = '11111111-1111-4111-8111-111111111111';
const OTHER_ID = '22222222-2222-4222-8222-222222222222';
const CALLER_SUB = 'google-sub-caller';
const OTHER_SUB = 'google-sub-someone-else';

const ENV = {
  SUPABASE_URL: 'https://project.supabase.test',
  SUPABASE_ANON_KEY: 'anon-key',
  SUPABASE_SERVICE_ROLE_KEY: 'service-role-key',
  GOOGLE_CLIENT_ID: 'client.apps.googleusercontent.com',
  NCKU_HOSTED_DOMAIN: 'gs.ncku.edu.tw',
  ALLOWED_ORIGINS: `${ORIGIN},http://localhost:5500`,
};

function buildHarness(overrides = {}) {
  const calls = { rpc: [], getUserById: [], verified: [], logs: [] };

  const state = {
    callerId: CALLER_ID,
    callerError: null,
    identities: [{ provider: 'google', provider_id: CALLER_SUB, id: 'identity-row-id' }],
    getUserByIdError: null,
    rpcError: null,
    rpcResult: [
      {
        user_id: CALLER_ID,
        email: 'student@gs.ncku.edu.tw',
        google_sub: CALLER_SUB,
        department: null,
        year: null,
        ncku_verified: true,
        is_active: true,
      },
    ],
    identity: { sub: CALLER_SUB, email: 'student@gs.ncku.edu.tw', hd: 'gs.ncku.edu.tw' },
    verifyError: null,
    ...overrides,
  };

  const createClient = (_url, key, options) => {
    if (key === ENV.SUPABASE_ANON_KEY) {
      return {
        authHeader: options?.global?.headers?.Authorization ?? null,
        auth: {
          getUser: async () =>
            state.callerError
              ? { data: null, error: state.callerError }
              : { data: { user: { id: state.callerId } }, error: null },
        },
      };
    }
    return {
      auth: {
        admin: {
          getUserById: async (id) => {
            calls.getUserById.push(id);
            return state.getUserByIdError
              ? { data: null, error: state.getUserByIdError }
              : { data: { user: { id, identities: state.identities } }, error: null };
          },
        },
      },
      rpc: async (name, args) => {
        calls.rpc.push({ name, args });
        return state.rpcError ? { data: null, error: state.rpcError } : { data: state.rpcResult, error: null };
      },
    };
  };

  const log = {
    error: (...args) => calls.logs.push(args),
    warn: (...args) => calls.logs.push(args),
  };

  const handler = createVerifyStudentHandler({
    env: { ...ENV, ...(overrides.env ?? {}) },
    createClient,
    log,
    verifyIdToken: async (token, options) => {
      calls.verified.push({ token, options });
      if (state.verifyError) throw state.verifyError;
      return state.identity;
    },
  });

  return { handler, calls, state };
}

const post = (body, { origin = ORIGIN, auth = 'Bearer caller-access-token', method = 'POST' } = {}) => {
  const headers = { 'Content-Type': 'application/json' };
  if (origin) headers.Origin = origin;
  if (auth) headers.Authorization = auth;
  return new Request('https://project.supabase.test/functions/v1/verify-ncku-student', {
    method,
    headers,
    body: method === 'POST' ? JSON.stringify(body ?? {}) : undefined,
  });
};

const read = async (response) => ({ status: response.status, body: await response.json() });

describe('verify-ncku-student', () => {
  let h;
  beforeEach(() => {
    h = buildHarness();
  });

  // -------------------------------------------------------------------
  // Account binding - the control that replaced the fake nonce
  // -------------------------------------------------------------------

  test('a verified NCKU token verifies the calling account', async () => {
    const { status, body } = await read(await h.handler(post({ id_token: 'good-token' })));
    assert.equal(status, 200);
    assert.equal(body.profile.user_id, CALLER_ID);
    assert.equal(body.profile.ncku_verified, true);
    assert.equal(h.calls.rpc.length, 1);
    assert.deepEqual(h.calls.rpc[0].args, {
      p_user_id: CALLER_ID,
      p_email: 'student@gs.ncku.edu.tw',
      p_google_sub: CALLER_SUB,
    });
  });

  test('student A cannot verify student B with their own Google token', async () => {
    // The caller is B (that is who the access token identifies), but the
    // Google identity linked to B does not carry A's subject.
    h = buildHarness({
      callerId: OTHER_ID,
      identities: [{ provider: 'google', provider_id: OTHER_SUB }],
      identity: { sub: CALLER_SUB, email: 'a@gs.ncku.edu.tw', hd: 'gs.ncku.edu.tw' },
    });

    const { status, body } = await read(await h.handler(post({ id_token: 'student-a-token' })));
    assert.equal(status, 403);
    assert.equal(body.error, 'identity_mismatch');
    assert.equal(h.calls.rpc.length, 0, 'nothing may be written when binding fails');
  });

  test('the request body cannot choose the account to verify', async () => {
    const { status, body } = await read(
      await h.handler(
        post({
          id_token: 'good-token',
          // Every one of these is ignored: the target is the JWT subject.
          user_id: OTHER_ID,
          p_user_id: OTHER_ID,
          email: 'victim@gs.ncku.edu.tw',
          ncku_verified: true,
          is_active: true,
          role: 'owner',
        })
      )
    );

    assert.equal(status, 200);
    assert.equal(body.profile.user_id, CALLER_ID);
    assert.deepEqual(h.calls.getUserById, [CALLER_ID]);
    assert.equal(h.calls.rpc[0].args.p_user_id, CALLER_ID);
    assert.equal(h.calls.rpc[0].args.p_email, 'student@gs.ncku.edu.tw', 'email comes from the token, not the body');
  });

  test('an account with no Google identity at all fails closed', async () => {
    h = buildHarness({ identities: [] });
    const { status, body } = await read(await h.handler(post({ id_token: 'good-token' })));
    assert.equal(status, 403);
    assert.equal(body.error, 'identity_mismatch');
    assert.equal(h.calls.rpc.length, 0);
  });

  test('an identity from another provider does not count as a Google binding', async () => {
    h = buildHarness({ identities: [{ provider: 'github', provider_id: CALLER_SUB }] });
    const { status } = await read(await h.handler(post({ id_token: 'good-token' })));
    assert.equal(status, 403);
  });

  test('the stable Google subject never reaches the logs', async () => {
    h = buildHarness({ identities: [] });
    await h.handler(post({ id_token: 'good-token' }));
    const logged = JSON.stringify(h.calls.logs);
    assert.ok(logged.length > 0, 'the failure is still logged');
    assert.ok(!logged.includes(CALLER_SUB), 'but not with the raw subject in it');
  });

  // -------------------------------------------------------------------
  // Token verification wiring
  // -------------------------------------------------------------------

  test('the hosted domain and client id come from the environment', async () => {
    await h.handler(post({ id_token: 'good-token' }));
    assert.deepEqual(h.calls.verified[0].options, {
      clientId: ENV.GOOGLE_CLIENT_ID,
      hostedDomain: 'gs.ncku.edu.tw',
    });
    assert.equal(h.calls.verified[0].token, 'good-token');
  });

  test('no nonce is sent to the verifier any more', async () => {
    await h.handler(post({ id_token: 'good-token', nonce: 'client-supplied' }));
    assert.ok(!('nonce' in h.calls.verified[0].options), 'a client-supplied nonce proves nothing');
  });

  test('a wrong hosted domain is reported as such, everything else is not', async () => {
    h = buildHarness({ verifyError: new IdTokenError('wrong_domain', 'nope') });
    assert.deepEqual(await read(await h.handler(post({ id_token: 't' }))), {
      status: 403,
      body: { error: 'wrong_domain' },
    });

    for (const code of ['invalid_signature', 'token_expired', 'invalid_algorithm', 'missing_claim', 'email_unverified']) {
      const one = buildHarness({ verifyError: new IdTokenError(code, code) });
      const { status, body } = await read(await one.handler(post({ id_token: 't' })));
      assert.equal(status, 403);
      assert.equal(body.error, 'invalid_token', `${code} must not leak its detail to the browser`);
    }
  });

  test('a misconfigured client id is a server error, not a rejected student', async () => {
    h = buildHarness({ verifyError: new IdTokenError('server_misconfigured', 'no client id') });
    const { status, body } = await read(await h.handler(post({ id_token: 't' })));
    assert.equal(status, 500);
    assert.equal(body.error, 'server_misconfigured');
  });

  // -------------------------------------------------------------------
  // Write failures are never silent
  // -------------------------------------------------------------------

  test('a failed verification write fails the request', async () => {
    // The RPC writes the profile and the audit entry in one transaction, so
    // there is no path where eligibility is granted without being recorded.
    h = buildHarness({ rpcError: { code: 'XX000', message: 'audit_log is unavailable' } });
    const { status, body } = await read(await h.handler(post({ id_token: 'good-token' })));
    assert.equal(status, 500);
    assert.equal(body.error, 'profile_write_failed');
    assert.ok(h.calls.logs.length > 0, 'and it is logged rather than swallowed');
  });

  test('a Google subject already bound to another account is refused', async () => {
    h = buildHarness({ rpcError: { code: '42501', message: 'google subject is already bound to another account' } });
    const { status, body } = await read(await h.handler(post({ id_token: 'good-token' })));
    assert.equal(status, 403);
    assert.equal(body.error, 'identity_mismatch');
  });

  test('an empty RPC result is a failure, not an empty profile', async () => {
    h = buildHarness({ rpcResult: [] });
    const { status, body } = await read(await h.handler(post({ id_token: 'good-token' })));
    assert.equal(status, 500);
    assert.equal(body.error, 'profile_write_failed');
  });

  test('the response never carries the Google subject', async () => {
    const { body } = await read(await h.handler(post({ id_token: 'good-token' })));
    assert.ok(!('google_sub' in body.profile));
    assert.deepEqual(Object.keys(body.profile).sort(), [
      'department', 'email', 'is_active', 'ncku_verified', 'user_id', 'year',
    ]);
  });

  // -------------------------------------------------------------------
  // Request handling
  // -------------------------------------------------------------------

  test('an unauthenticated request never reaches the token check', async () => {
    for (const auth of [null, 'caller-access-token', 'Basic abc']) {
      const one = buildHarness();
      const { status, body } = await read(await one.handler(post({ id_token: 't' }, { auth })));
      assert.equal(status, 401);
      assert.equal(body.error, 'unauthenticated');
      assert.equal(one.calls.verified.length, 0);
    }
  });

  test('a rejected access token is unauthenticated', async () => {
    h = buildHarness({ callerError: { message: 'jwt expired' } });
    const { status } = await read(await h.handler(post({ id_token: 't' })));
    assert.equal(status, 401);
  });

  test('only POST is answered', async () => {
    const { status } = await read(await h.handler(post(null, { method: 'GET' })));
    assert.equal(status, 405);
  });

  test('a preflight is answered without a body', async () => {
    const response = await h.handler(post(null, { method: 'OPTIONS' }));
    assert.equal(response.status, 204);
    assert.equal(response.headers.get('Access-Control-Allow-Origin'), ORIGIN);
  });

  test('an unparseable body is a bad request', async () => {
    const request = new Request('https://project.supabase.test/functions/v1/verify-ncku-student', {
      method: 'POST',
      headers: { Origin: ORIGIN, Authorization: 'Bearer token', 'Content-Type': 'application/json' },
      body: 'not json',
    });
    const { status, body } = await read(await h.handler(request));
    assert.equal(status, 400);
    assert.equal(body.error, 'invalid_request');
  });

  // -------------------------------------------------------------------
  // Origin handling fails closed
  // -------------------------------------------------------------------

  test('an unconfigured allowlist refuses every request', async () => {
    h = buildHarness({ env: { ALLOWED_ORIGINS: '' } });
    const response = await h.handler(post({ id_token: 'good-token' }));
    assert.equal(response.status, 500);
    assert.equal((await response.json()).error, 'server_misconfigured');
    assert.equal(response.headers.get('Access-Control-Allow-Origin'), null, 'and never answers with a wildcard');
    assert.equal(h.calls.rpc.length, 0);
  });

  test('an origin outside the allowlist is refused', async () => {
    const response = await h.handler(post({ id_token: 'good-token' }, { origin: 'https://phish.example' }));
    assert.equal(response.status, 403);
    assert.equal((await response.json()).error, 'origin_not_allowed');
    assert.equal(response.headers.get('Access-Control-Allow-Origin'), null);
  });

  test('an allowed origin is echoed back, never a wildcard', async () => {
    const response = await h.handler(post({ id_token: 'good-token' }, { origin: 'http://localhost:5500' }));
    assert.equal(response.headers.get('Access-Control-Allow-Origin'), 'http://localhost:5500');
    assert.equal(response.headers.get('Vary'), 'Origin');
  });
});
