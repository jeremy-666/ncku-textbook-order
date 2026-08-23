// Trusted verification of a Google ID token.
//
// This is the ONLY thing that may establish NCKU student eligibility. An email
// that merely ends in "@gs.ncku.edu.tw" proves nothing: the authorization
// signal is the `hd` claim inside a token whose algorithm, signature, issuer,
// audience, authorized party, issue time and expiry have all been checked
// against Google's JWKS.
//
// Imported by both the Deno edge function and the Node test suite, so it
// stays free of any runtime-specific API.
//
// What this file does NOT do: replay protection. A previous version compared
// the token's `nonce` against a value the same client had just supplied, which
// proves nothing an attacker holding the token could not also satisfy. Real
// replay protection needs a server-issued, server-stored, single-use nonce.
// The control that actually binds a token to an account lives in the edge
// function: the Google `sub` must match an identity already linked to the
// Supabase user being verified.

import { createRemoteJWKSet, jwtVerify } from 'jose';

export const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];
export const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
export const NCKU_HOSTED_DOMAIN = 'gs.ncku.edu.tw';

// Google signs ID tokens with RS256. Naming it explicitly stops a token from
// choosing its own verification algorithm.
export const ALLOWED_ALGORITHMS = ['RS256'];

// Google ID tokens are valid for an hour, but this one is minted by the sign-in
// that is happening right now and posted immediately. Ten minutes covers slow
// networks and modest clock skew while keeping a leaked token short-lived.
export const MAX_TOKEN_AGE_SEC = 600;

// Security-critical claims. A token missing any of them is not something to
// interpret generously.
export const REQUIRED_CLAIMS = ['exp', 'iat', 'iss', 'aud', 'sub'];

export class IdTokenError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'IdTokenError';
    this.code = code;
  }
}

let remoteJwks;

/** Cached remote key set - jose handles rotation and caching internally. */
export function googleJwks() {
  remoteJwks ??= createRemoteJWKSet(new URL(GOOGLE_JWKS_URL));
  return remoteJwks;
}

// jose reports each failed check with its own code; map them so the caller can
// log precisely without leaking detail to the browser.
function mapJoseError(error) {
  switch (error?.code) {
    case 'ERR_JOSE_ALG_NOT_ALLOWED':
      return new IdTokenError('invalid_algorithm', 'Google ID token used an unsupported algorithm');
    case 'ERR_JWT_EXPIRED':
      // maxTokenAge failures arrive here too, tagged with the iat claim.
      return error.claim === 'iat'
        ? new IdTokenError('token_too_old', 'Google ID token was issued too long ago')
        : new IdTokenError('token_expired', 'Google ID token has expired');
    case 'ERR_JWT_CLAIM_VALIDATION_FAILED':
      if (error.reason === 'missing') {
        return new IdTokenError('missing_claim', `Google ID token is missing the "${error.claim}" claim`);
      }
      return new IdTokenError(
        error.claim === 'aud' ? 'invalid_audience'
          : error.claim === 'iss' ? 'invalid_issuer'
          : error.claim === 'iat' ? 'invalid_issued_at'
          : 'invalid_claims',
        `Google ID token claim "${error.claim}" failed validation`
      );
    case 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED':
    case 'ERR_JWKS_NO_MATCHING_KEY':
      return new IdTokenError('invalid_signature', 'Google ID token signature could not be verified');
    default:
      return new IdTokenError('invalid_token', 'Google ID token could not be verified');
  }
}

/**
 * @param {string} token          raw Google ID token (JWT)
 * @param {object} options
 * @param {string} options.clientId          expected `aud` (and `azp`, when present)
 * @param {string} [options.hostedDomain]    required `hd`, defaults to gs.ncku.edu.tw
 * @param {*}      [options.jwks]            key resolver; tests inject a local one
 * @param {number} [options.maxTokenAgeSec]  reject tokens issued longer ago than this
 * @returns {Promise<{sub: string, email: string, hd: string, name?: string}>}
 */
export async function verifyGoogleIdToken(token, options = {}) {
  const {
    clientId,
    hostedDomain = NCKU_HOSTED_DOMAIN,
    jwks = googleJwks(),
    clockToleranceSec = 5,
    maxTokenAgeSec = MAX_TOKEN_AGE_SEC,
  } = options;

  if (!clientId) {
    throw new IdTokenError('server_misconfigured', 'GOOGLE_CLIENT_ID is not configured');
  }
  if (typeof token !== 'string' || token.split('.').length !== 3) {
    throw new IdTokenError('invalid_token', 'Missing or malformed Google ID token');
  }

  let payload;
  try {
    ({ payload } = await jwtVerify(token, jwks, {
      algorithms: ALLOWED_ALGORITHMS,
      issuer: GOOGLE_ISSUERS,
      audience: clientId,
      requiredClaims: REQUIRED_CLAIMS,
      maxTokenAge: maxTokenAgeSec,
      clockTolerance: clockToleranceSec,
    }));
  } catch (error) {
    throw mapJoseError(error);
  }

  // jose accepts a token whose `aud` array merely CONTAINS our client id. That
  // is a token issued to somebody else which happens to name us, and per the
  // OpenID Connect rules it is only interpretable with `azp`. We accept one
  // client, so: a multi-audience token must carry azp, and any azp present at
  // all must be exactly our client.
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (audiences.length > 1 && payload.azp === undefined) {
    throw new IdTokenError('invalid_audience', 'Multi-audience Google ID token has no azp claim');
  }
  if (payload.azp !== undefined && payload.azp !== clientId) {
    throw new IdTokenError('invalid_audience', 'Google ID token was issued to another client');
  }

  if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
    throw new IdTokenError('invalid_token', 'Google ID token has no subject');
  }
  if (payload.email_verified !== true) {
    throw new IdTokenError('email_unverified', 'Google account email is not verified');
  }

  // The authorization decision. A missing hd (personal gmail.com account) and
  // a foreign hd are both rejected, and neither can be faked without Google's
  // signing key.
  if (payload.hd !== hostedDomain) {
    throw new IdTokenError('wrong_domain', `Google account is not a member of ${hostedDomain}`);
  }

  return {
    sub: payload.sub,
    email: typeof payload.email === 'string' ? payload.email.toLowerCase() : '',
    hd: payload.hd,
    name: typeof payload.name === 'string' ? payload.name : undefined,
  };
}
