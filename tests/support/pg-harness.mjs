// A disposable PostgreSQL for the migrations.
//
// PGlite is a real PostgreSQL server compiled to WASM, running in-process and
// discarded when the test ends. It is NOT Supabase: there is no PostgREST, no
// GoTrue, no service-role JWT. What it does give us is the thing static review
// cannot - the migrations actually executing, and RLS actually deciding.
//
// Two ownership modes, because the answer differs between deployments:
//
//   'superuser'  - migrations applied by a superuser that bypasses RLS even
//                  where FORCE is set. This is how Supabase behaves if its
//                  `postgres` role holds BYPASSRLS.
//   'plain'      - migrations applied by a NOSUPERUSER role without BYPASSRLS,
//                  so FORCE ROW LEVEL SECURITY applies to the SECURITY DEFINER
//                  helpers too. This is the pessimistic case, and the one the
//                  definer policies in 20260823000200_rls.sql exist for.
//
// Everything must pass in both modes. If it only passes as superuser, the
// design is relying on an attribute nobody promised us.

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { pgcrypto } from '@electric-sql/pglite/contrib/pgcrypto';

const MIGRATIONS = [
  '../../supabase/migrations/20260823000100_auth_core.sql',
  '../../supabase/migrations/20260823000200_rls.sql',
  '../../supabase/migrations/20260823000300_revoke_verification_rpc.sql',
  '../../supabase/migrations/20260823000400_harden_function_privileges.sql',
  '../../supabase/migrations/20260823000500_revoke_privilege_probe_public.sql',
];

export const OWNER_MODES = ['superuser', 'plain'];

/** Minimal stand-in for the parts of Supabase Auth the schema references. */
const AUTH_STUB = `
create schema if not exists auth;

create table if not exists auth.users (
  id    uuid primary key,
  email text
);

create or replace function auth.uid() returns uuid
language sql stable as $$
  select nullif(current_setting('request.jwt.claims', true)::json ->> 'sub', '')::uuid;
$$;

create role anon nologin;
create role authenticated nologin;
create role service_role nologin bypassrls;

grant usage on schema auth to anon, authenticated, service_role;
grant usage on schema public to anon, authenticated, service_role;
`;

export async function createHarness({ ownerMode = 'superuser' } = {}) {
  const db = await PGlite.create({ extensions: { pgcrypto } });

  await db.exec(AUTH_STUB);
  await db.exec('create extension if not exists pgcrypto;');

  let owner = 'postgres';
  if (ownerMode === 'plain') {
    owner = 'app_owner';
    await db.exec(`
      create role app_owner nosuperuser nobypassrls nologin;
      grant create, usage on schema public to app_owner;
      grant usage on schema auth to app_owner;
      grant references, select on auth.users to app_owner;
      grant anon, authenticated, service_role to app_owner with admin option;
    `);
  }

  await db.exec(`set role ${owner};`);
  // Supabase installs direct API-role EXECUTE defaults for newly created
  // functions. The migrations must revoke these explicitly, not merely PUBLIC.
  await db.exec(`alter default privileges in schema public grant execute on functions to anon, authenticated, service_role;`);
  for (const relative of MIGRATIONS) {
    const sql = await readFile(fileURLToPath(new URL(relative, import.meta.url)), 'utf8');
    await db.exec(sql);
  }
  // Supabase hands service_role every privilege on public and exempts it from
  // RLS. Mirror that here so fixture setup behaves the way the edge function
  // and the dashboard do, in both ownership modes.
  await db.exec(`
    grant all on all tables in schema public to service_role;
    grant all on all sequences in schema public to service_role;
    grant execute on all functions in schema public to service_role;
  `);
  await db.exec('reset role;');

  const state = { db, owner, ownerMode, users: new Map() };
  return {
    ...state,

    /** Create an auth.users row and return its id. */
    async addUser(name) {
      const id = await db
        .query('select gen_random_uuid() as id')
        .then((r) => r.rows[0].id);
      await db.query('insert into auth.users (id, email) values ($1, $2)', [id, `${name}@example.test`]);
      state.users.set(name, id);
      return id;
    },

    id(name) {
      const value = state.users.get(name);
      if (!value) throw new Error(`unknown test user: ${name}`);
      return value;
    },

    /** Run SQL exactly as PostgREST would for that Supabase role. */
    async as(role, userId, sql, params = []) {
      const claims = userId === null ? { role } : { role, sub: userId };
      await db.exec(`set role ${role};`);
      await db.query('select set_config($1, $2, false)', ['request.jwt.claims', JSON.stringify(claims)]);
      try {
        return { rows: (await db.query(sql, params)).rows, error: null };
      } catch (error) {
        return { rows: null, error: normalize(error) };
      } finally {
        await db.exec('reset role;');
        await db.query('select set_config($1, $2, false)', ['request.jwt.claims', '']);
      }
    },

    /** API role with no JWT claims: models an unauthenticated PostgREST call. */
    async asWithoutClaims(role, sql, params = []) {
      await db.exec(`set role ${role};`);
      await db.query("select set_config('request.jwt.claims', '{}', false)");
      try {
        const result = await db.query(sql, params);
        return { rows: result.rows, error: null };
      } catch (error) {
        return { rows: [], error: normalize(error) };
      } finally {
        await db.exec('reset role;');
        await db.query("select set_config('request.jwt.claims', '{}', false)");
      }
    },

    /**
     * Multiple statements in ONE implicit transaction, as that role. Needed to
     * test whether a client can smuggle a transaction-local GUC into its own
     * statement - a parameterised query cannot carry two commands.
     */
    async asExec(role, userId, sql) {
      const claims = userId === null ? { role } : { role, sub: userId };
      await db.exec(`set role ${role};`);
      await db.query('select set_config($1, $2, false)', ['request.jwt.claims', JSON.stringify(claims)]);
      try {
        return { rows: null, error: null, result: await db.exec(sql) };
      } catch (error) {
        return { rows: null, error: normalize(error) };
      } finally {
        await db.exec('reset role;');
        await db.query('select set_config($1, $2, false)', ['request.jwt.claims', '']);
        await db.query('select set_config($1, $2, false)', ['app.student_ctx', 'off']);
      }
    },

    /** Fixture setup as service_role: the same bypass the edge function has. */
    async priv(sql, params = []) {
      await db.exec('set role service_role;');
      await db.query('select set_config($1, $2, false)', ['request.jwt.claims', JSON.stringify({ role: 'service_role' })]);
      try {
        return (await db.query(sql, params)).rows;
      } finally {
        await db.exec('reset role;');
        await db.query('select set_config($1, $2, false)', ['request.jwt.claims', '']);
      }
    },

    async close() {
      await db.close();
    },
  };
}

/** PostgreSQL errors, reduced to the fields the assertions care about. */
function normalize(error) {
  return {
    code: error?.code ?? null,
    message: `${error?.message ?? error}`,
    detail: error?.detail ?? null,
  };
}

/**
 * Denial taxonomy. A test that accepts "an error, any error" cannot tell a
 * privilege denial from a typo, so every denial assertion names its kind.
 */
export const DENIAL = {
  /** GRANT-level refusal: the role never had the privilege on that table/column. */
  privilege: (error) =>
    error?.code === '42501' && /permission denied/i.test(error.message),
  /** RLS WITH CHECK refusal: the row was not allowed to exist that way. */
  rls: (error) =>
    error?.code === '42501' && /row-level security/i.test(error.message),
  /** A guard trigger refused the statement explicitly. */
  guard: (error) =>
    error?.code === '42501' && !/permission denied|row-level security/i.test(error.message),
  /** Any of the three - only for assertions where the kind genuinely is open. */
  any: (error) => error?.code === '42501',
};
