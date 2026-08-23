// Database authorization against a live Supabase project.
//
// tests/sql-policies.test.mjs proves the policies decide correctly inside
// PostgreSQL. This suite proves the same thing through PostgREST, GoTrue and
// the real Supabase roles - the parts an in-process PostgreSQL cannot model.
// Every client below is a genuine end-user session; the service-role client
// only ever arranges fixtures.
//
//   npm run test:security       (requires .env, fails if it is missing)
//   npm test                    (skips this file and says so)
//
// Point it at a scratch project. It creates and deletes users.

import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createClient } from '@supabase/supabase-js';

const URL = process.env.SUPABASE_URL;
const ANON = process.env.SUPABASE_ANON_KEY;
const SERVICE = process.env.SUPABASE_SERVICE_ROLE_KEY;
const REQUIRED = process.env.NCKU_REQUIRE_DB === '1';

const missing = [
  ['SUPABASE_URL', URL],
  ['SUPABASE_ANON_KEY', ANON],
  ['SUPABASE_SERVICE_ROLE_KEY', SERVICE],
]
  .filter(([, value]) => !value)
  .map(([name]) => name);

if (REQUIRED && missing.length > 0) {
  // Security mode must not be able to report success without ever asking a
  // database anything.
  throw new Error(
    `NCKU_REQUIRE_DB=1 but ${missing.join(', ')} ${missing.length === 1 ? 'is' : 'are'} not set. ` +
      'Live RLS verification cannot run, and unit tests do not substitute for it.'
  );
}

const skip = missing.length === 0 ? false : `set ${missing.join(', ')} to run the live RLS suite`;

const PASSWORD = 'Test-Password-9f2b!';
const run = Date.now().toString(36);
const tag = (name) => `rls-${run}-${name}@example.test`;

let service;
const users = {}; // name -> user id
const as = {};    // name -> authenticated supabase client
const forms = {}; // name -> form id

/**
 * Denial taxonomy. "Some error happened" is not an assertion: a typo would
 * satisfy it. Each helper names the boundary that is supposed to refuse.
 */
const denied = {
  privilege: (error) => error?.code === '42501' && /permission denied/i.test(error.message ?? ''),
  rls: (error) => error?.code === '42501' && /row-level security/i.test(error.message ?? ''),
  guard: (error) =>
    error?.code === '42501' && !/permission denied|row-level security/i.test(error.message ?? ''),
};

const expect = {
  privilege(result, label) {
    assert.ok(denied.privilege(result.error), `${label}: expected a privilege refusal, got ${describeResult(result)}`);
  },
  rls(result, label) {
    assert.ok(denied.rls(result.error), `${label}: expected an RLS refusal, got ${describeResult(result)}`);
  },
  guard(result, label) {
    assert.ok(denied.guard(result.error), `${label}: expected a guard trigger refusal, got ${describeResult(result)}`);
  },
  /** RLS filtered the row out: the statement succeeded and touched nothing. */
  noRows(result, label) {
    assert.equal(result.error, null, `${label}: expected no error, got ${result.error?.message}`);
    assert.equal(result.data?.length ?? 0, 0, `${label}: expected zero rows, got ${result.data?.length}`);
  },
};

const describeResult = (result) =>
  result.error ? `${result.error.code} ${result.error.message}` : `success with ${result.data?.length ?? 0} row(s)`;

async function newUser(name) {
  const { data, error } = await service.auth.admin.createUser({
    email: tag(name),
    password: PASSWORD,
    email_confirm: true,
  });
  if (error) throw error;
  users[name] = data.user.id;

  const client = createClient(URL, ANON, { auth: { persistSession: false, autoRefreshToken: false } });
  const { error: signInError } = await client.auth.signInWithPassword({ email: tag(name), password: PASSWORD });
  if (signInError) throw signInError;
  as[name] = client;
  return data.user.id;
}

/** A signed-out client, i.e. someone who deleted the frontend entirely. */
const anonymous = () => createClient(URL, ANON, { auth: { persistSession: false, autoRefreshToken: false } });

describe('row level security', { skip }, () => {
  before(async () => {
    service = createClient(URL, SERVICE, { auth: { persistSession: false, autoRefreshToken: false } });

    // Fail loudly and specifically if the migrations were never applied,
    // rather than failing 30 assertions with confusing messages.
    const probe = await service.from('audit_log').select('organization').limit(1);
    if (probe.error) {
      throw new Error(
        `The migrations do not appear to be applied to ${URL}: ${probe.error.message}. ` +
          'Apply supabase/migrations/*.sql before running the security suite.'
      );
    }
    // PostgREST answers PGRST202 both for "no such function" and for "no
    // overload with those argument names", so each probe passes the real
    // parameter names. Every one of them then refuses on its own terms
    // (missing argument, or not an administrator) without writing anything.
    const probes = [
      ['record_student_verification', { p_user_id: null, p_email: '', p_google_sub: '' }],
      ['lookup_student_for_assignment', { p_email: '' }],
      ['set_student_active', { p_student_user_id: null, p_active: null, p_reason: null }],
    ];
    for (const [fn, args] of probes) {
      const { error } = await service.rpc(fn, args);
      if (error?.code === 'PGRST202') {
        throw new Error(`Migration incomplete: ${fn}() is missing from ${URL} (${error.message}).`);
      }
    }
    const privilegeProbe = await service.rpc('assert_api_function_privileges');
    if (privilegeProbe.error) {
      throw new Error(`Migration privilege drift detected: ${privilegeProbe.error.code} ${privilegeProbe.error.message}`);
    }

    await Promise.all(
      [
        'studentA', 'studentB', 'studentSuspended', 'nobody',
        'liwenEditor', 'liwenOwner', 'suEditor', 'suOwner', 'retiredAdmin',
      ].map(newUser)
    );

    const profile = (name, extra = {}) => ({
      user_id: users[name],
      email: tag(name),
      google_sub: `sub-${run}-${name}`,
      department: '資訊工程學系',
      year: 2,
      ncku_verified: true,
      is_active: true,
      verified_at: new Date().toISOString(),
      ...extra,
    });

    let { error } = await service.from('student_profiles').insert([
      profile('studentA'),
      profile('studentB'),
      profile('studentSuspended', { is_active: false }),
    ]);
    if (error) throw error;

    ({ error } = await service.from('admin_users').insert([
      { user_id: users.liwenEditor, organization: 'liwen', display_name: 'Liwen Editor', role: 'editor', is_active: true },
      { user_id: users.liwenOwner, organization: 'liwen', display_name: 'Liwen Owner', role: 'owner', is_active: true },
      { user_id: users.suEditor, organization: 'student_union', display_name: 'SU Editor', role: 'editor', is_active: true },
      { user_id: users.suOwner, organization: 'student_union', display_name: 'SU Owner', role: 'owner', is_active: true },
      { user_id: users.retiredAdmin, organization: 'liwen', display_name: 'Retired', role: 'editor', is_active: false },
    ]));
    if (error) throw error;

    const { data: createdForms, error: formError } = await service
      .from('forms')
      .insert([
        { title: `assigned-${run}`, organization: 'liwen', status: 'open', created_by: users.liwenEditor, fields: [] },
        { title: `unassigned-${run}`, organization: 'liwen', status: 'open', created_by: users.liwenEditor, fields: [] },
        { title: `draft-${run}`, organization: 'liwen', status: 'draft', created_by: users.liwenEditor, fields: [] },
        { title: `closed-${run}`, organization: 'liwen', status: 'closed', created_by: users.liwenEditor, fields: [] },
        { title: `union-${run}`, organization: 'student_union', status: 'open', created_by: users.suEditor, fields: [] },
      ])
      .select('id, title');
    if (formError) throw formError;
    for (const form of createdForms) forms[form.title.split('-')[0]] = form.id;

    // studentA belongs to Liwen forms only; studentB to the Student Union one.
    ({ error } = await service.from('form_assignments').insert([
      ...['assigned', 'draft', 'closed'].map((key) => ({
        form_id: forms[key],
        student_user_id: users.studentA,
        assigned_by: users.liwenEditor,
      })),
      { form_id: forms.union, student_user_id: users.studentB, assigned_by: users.suEditor },
    ]));
    if (error) throw error;
  });

  after(async () => {
    if (!service) return;
    const ids = Object.values(users);
    // Delete children first: the audit trail is keyed on ids that are about to
    // disappear, and forms cascade into assignments and submissions.
    await service.from('form_submissions').delete().in('student_user_id', ids);
    await service.from('form_assignments').delete().in('student_user_id', ids);
    await service.from('forms').delete().like('title', `%-${run}`);
    await service.from('admin_users').delete().in('user_id', ids);
    await service.from('student_profiles').delete().in('user_id', ids);
    await service.from('audit_log').delete().in('actor_user_id', ids);
    await service.from('audit_log').delete().in('target_id', ids);
    for (const id of ids) await service.auth.admin.deleteUser(id);
  });

  // -------------------------------------------------------------------
  // Organization isolation
  // -------------------------------------------------------------------

  test('each organization sees only its own forms', async () => {
    const liwen = await as.liwenEditor.from('forms').select('id, organization');
    assert.equal(liwen.error, null);
    assert.ok(liwen.data.length >= 4);
    assert.ok(liwen.data.every((row) => row.organization === 'liwen'));

    const union = await as.suEditor.from('forms').select('id, organization');
    assert.ok(union.data.every((row) => row.organization === 'student_union'));
    assert.ok(!union.data.some((row) => row.id === forms.assigned));
  });

  test('a Liwen editor cannot read, update or delete a Student Union form', async () => {
    expect.noRows(await as.liwenEditor.from('forms').select('id').eq('id', forms.union), 'cross-org read');
    expect.noRows(
      await as.liwenEditor.from('forms').update({ title: 'taken over' }).eq('id', forms.union).select('id'),
      'cross-org update'
    );
    expect.noRows(
      await as.liwenOwner.from('forms').delete().eq('id', forms.union).select('id'),
      'cross-org delete by an owner'
    );

    const { data } = await service.from('forms').select('title').eq('id', forms.union).single();
    assert.equal(data.title, `union-${run}`);
  });

  test('a Student Union editor cannot read, update or delete a Liwen form', async () => {
    expect.noRows(await as.suEditor.from('forms').select('id').eq('id', forms.assigned), 'cross-org read');
    expect.noRows(
      await as.suEditor.from('forms').update({ status: 'closed' }).eq('id', forms.assigned).select('id'),
      'cross-org update'
    );
    expect.noRows(
      await as.suOwner.from('forms').delete().eq('id', forms.assigned).select('id'),
      'cross-org delete by an owner'
    );
  });

  test('cross-organization assignment is refused', async () => {
    expect.rls(
      await as.liwenEditor.from('form_assignments').insert({
        form_id: forms.union,
        student_user_id: users.studentA,
        assigned_by: users.liwenEditor,
      }),
      'assigning into the other organization'
    );

    expect.noRows(
      await as.suEditor.from('form_assignments').delete().eq('form_id', forms.assigned).select('id'),
      'un-assigning in the other organization'
    );
  });

  test('submissions stay inside the organization that owns the form', async () => {
    await service.from('form_submissions').insert({
      form_id: forms.union,
      student_user_id: users.studentB,
      answers: { secret: 'union only' },
      status: 'submitted',
    });

    const union = await as.suEditor.from('form_submissions').select('id, answers');
    assert.ok(union.data.length >= 1);

    const liwen = await as.liwenEditor.from('form_submissions').select('id').eq('form_id', forms.union);
    expect.noRows(liwen, 'cross-org submission read');
  });

  test('organization cannot be forged through the request payload', async () => {
    expect.rls(
      await as.liwenEditor
        .from('forms')
        .insert({ title: `forged-${run}`, organization: 'student_union', created_by: users.liwenEditor }),
      'creating a form for the other organization'
    );

    expect.guard(
      await as.liwenEditor.from('forms').update({ organization: 'student_union' }).eq('id', forms.assigned),
      'moving a form to the other organization'
    );
  });

  test('the audit trail is organization-scoped', async () => {
    await as.liwenEditor.from('forms').update({ description: 'touched' }).eq('id', forms.assigned);

    const liwen = await as.liwenEditor.from('audit_log').select('organization');
    assert.ok(liwen.data.length >= 1);
    assert.ok(liwen.data.every((row) => row.organization === 'liwen'));

    const union = await as.suEditor.from('audit_log').select('organization');
    assert.ok(union.data.every((row) => row.organization === 'student_union'));
  });

  // -------------------------------------------------------------------
  // Student privacy
  // -------------------------------------------------------------------

  test('an administrator sees only students assigned to their own forms', async () => {
    const liwen = await as.liwenEditor.from('student_profiles').select('user_id');
    assert.deepEqual(liwen.data.map((row) => row.user_id), [users.studentA]);

    const union = await as.suEditor.from('student_profiles').select('user_id');
    assert.deepEqual(union.data.map((row) => row.user_id), [users.studentB]);
  });

  test('the assignment lookup answers one email and nothing more', async () => {
    const hit = await as.liwenEditor.rpc('lookup_student_for_assignment', { p_email: tag('studentB').toUpperCase() });
    assert.equal(hit.error, null);
    assert.deepEqual(hit.data, [{ user_id: users.studentB, assignable: true }]);

    const miss = await as.liwenEditor.rpc('lookup_student_for_assignment', { p_email: 'nobody@example.test' });
    assert.deepEqual(miss.data, []);

    const dump = await as.liwenEditor.rpc('lookup_student_for_assignment', { p_email: '' });
    assert.deepEqual(dump.data, [], 'an empty needle is not a roster dump');

    expect.guard(
      await as.studentA.rpc('lookup_student_for_assignment', { p_email: tag('studentB') }),
      'a student using the lookup'
    );
  });

  test('student A cannot read student B private data', async () => {
    const own = await as.studentA.from('student_profiles').select('user_id, email').eq('user_id', users.studentA);
    assert.equal(own.data.length, 1);

    expect.noRows(
      await as.studentA.from('student_profiles').select('user_id').eq('user_id', users.studentB),
      'reading another student profile'
    );

    const all = await as.studentA.from('student_profiles').select('user_id');
    assert.deepEqual(all.data.map((row) => row.user_id), [users.studentA]);
  });

  test('student A cannot read student B submissions', async () => {
    expect.noRows(
      await as.studentA.from('form_submissions').select('id').eq('student_user_id', users.studentB),
      'reading another student submission'
    );
  });

  // -------------------------------------------------------------------
  // Students cannot escalate
  // -------------------------------------------------------------------

  test('a student cannot set their own ncku_verified or is_active', async () => {
    expect.privilege(
      await as.studentA.from('student_profiles').update({ ncku_verified: true }).eq('user_id', users.studentA),
      'writing ncku_verified'
    );
    expect.privilege(
      await as.studentSuspended
        .from('student_profiles')
        .update({ is_active: true })
        .eq('user_id', users.studentSuspended),
      'reactivating themselves'
    );

    const { data } = await service
      .from('student_profiles')
      .select('is_active')
      .eq('user_id', users.studentSuspended)
      .single();
    assert.equal(data.is_active, false);
  });

  test('user_metadata is not authorization', async () => {
    // The forged-metadata case: everything a user could ever influence about
    // themselves, set as favourably as possible.
    await service.auth.admin.updateUserById(users.studentA, {
      user_metadata: {
        role: 'owner',
        is_admin: true,
        organization: 'student_union',
        ncku_verified: true,
        admin: true,
      },
      app_metadata: { claims_admin: true },
    });

    const client = createClient(URL, ANON, { auth: { persistSession: false, autoRefreshToken: false } });
    const { error: signInError } = await client.auth.signInWithPassword({
      email: tag('studentA'),
      password: PASSWORD,
    });
    assert.equal(signInError, null);

    const { data: session } = await client.auth.getUser();
    assert.equal(session.user.user_metadata.is_admin, true, 'the metadata really is on the account');

    expect.noRows(await client.from('admin_users').select('user_id'), 'admin_users with forged metadata');
    expect.noRows(await client.from('audit_log').select('id'), 'audit_log with forged metadata');
    const visible = await client.from('forms').select('id');
    assert.ok(!visible.data.some((row) => row.id === forms.union), 'and no reach into the other organization');
  });

  test('a student cannot make themselves an administrator', async () => {
    expect.rls(
      await as.studentA.from('admin_users').insert({
        user_id: users.studentA,
        organization: 'liwen',
        display_name: 'definitely an admin',
        role: 'owner',
      }),
      'self-inserting an admin row'
    );
  });

  test('a student sees nothing in admin_users or audit_log', async () => {
    expect.noRows(await as.studentA.from('admin_users').select('user_id'), 'admin_users');
    expect.noRows(await as.studentA.from('audit_log').select('id'), 'audit_log');
  });

  // -------------------------------------------------------------------
  // Forms and assignments
  // -------------------------------------------------------------------

  test('a student sees only assigned, non-draft forms', async () => {
    const { data } = await as.studentA.from('forms').select('id');
    assert.deepEqual(
      data.map((row) => row.id).sort(),
      [forms.assigned, forms.closed].sort(),
      'assigned + closed only; the draft stays hidden'
    );

    expect.noRows(await as.studentA.from('forms').select('id').eq('id', forms.unassigned), 'unassigned form');
    expect.noRows(await as.studentA.from('forms').select('id').eq('id', forms.union), 'other organization form');
  });

  test('a student cannot create or edit a form', async () => {
    expect.rls(
      await as.studentA.from('forms').insert({ title: `hacked-${run}`, organization: 'liwen', created_by: users.studentA }),
      'creating a form'
    );
    expect.noRows(
      await as.studentA.from('forms').update({ title: 'renamed by a student' }).eq('id', forms.assigned).select('id'),
      'editing a form'
    );
  });

  test('a student cannot assign forms to anybody', async () => {
    expect.rls(
      await as.studentA.from('form_assignments').insert({
        form_id: forms.unassigned,
        student_user_id: users.studentA,
        assigned_by: users.studentA,
      }),
      'self-assignment'
    );
  });

  // -------------------------------------------------------------------
  // Submissions
  // -------------------------------------------------------------------

  test('a student can submit to an assigned open form', async () => {
    const { data, error } = await as.studentA
      .from('form_submissions')
      .insert({ form_id: forms.assigned, student_user_id: users.studentA, answers: { book: '計算機概論' }, status: 'submitted' })
      .select('id, submitted_at');
    assert.equal(error, null);
    assert.equal(data.length, 1);
    assert.ok(data[0].submitted_at, 'submitted_at is stamped by the server');
  });

  test('a submission cannot be created for the wrong form or the wrong student', async () => {
    expect.rls(
      await as.studentA.from('form_submissions').insert({
        form_id: forms.unassigned,
        student_user_id: users.studentA,
        answers: {},
      }),
      'unassigned form'
    );
    expect.rls(
      await as.studentA.from('form_submissions').insert({
        form_id: forms.assigned,
        student_user_id: users.studentB,
        answers: {},
      }),
      'on behalf of another student'
    );
    expect.rls(
      await as.studentA.from('form_submissions').insert({
        form_id: forms.closed,
        student_user_id: users.studentA,
        answers: {},
      }),
      'closed form'
    );
  });

  test('submission identity cannot be rewritten', async () => {
    const { data: mine } = await as.studentA.from('form_submissions').select('id').eq('form_id', forms.assigned).single();

    expect.guard(
      await as.studentA.from('form_submissions').update({ form_id: forms.closed }).eq('id', mine.id),
      'form_id rewrite'
    );
    expect.guard(
      await as.studentA.from('form_submissions').update({ student_user_id: users.studentB }).eq('id', mine.id),
      'student_user_id rewrite'
    );
    expect.guard(
      await as.studentA.from('form_submissions').update({ id: users.studentB }).eq('id', mine.id),
      'primary key rewrite'
    );
  });

  test('submission timestamps stay server-controlled', async () => {
    const { data } = await as.studentA
      .from('form_submissions')
      .update({ answers: { book: 'edited' }, submitted_at: '2000-01-01T00:00:00Z', created_at: '2000-01-01T00:00:00Z' })
      .eq('form_id', forms.assigned)
      .select('submitted_at, created_at');
    assert.equal(data.length, 1);
    assert.ok(new Date(data[0].submitted_at).getUTCFullYear() >= 2026, 'submitted_at cannot be backdated');
    assert.ok(new Date(data[0].created_at).getUTCFullYear() >= 2026, 'created_at cannot be backdated');
  });

  test('a submission cannot be edited after the assignment is removed', async () => {
    const { data: assignment } = await service
      .from('form_assignments')
      .select('id')
      .eq('form_id', forms.union)
      .eq('student_user_id', users.studentB)
      .single();
    await service.from('form_assignments').delete().eq('id', assignment.id);

    expect.noRows(
      await as.studentB
        .from('form_submissions')
        .update({ answers: { book: 'late edit' } })
        .eq('form_id', forms.union)
        .select('id'),
      'editing after un-assignment'
    );

    await service
      .from('form_assignments')
      .insert({ form_id: forms.union, student_user_id: users.studentB, assigned_by: users.suEditor });
  });

  test('a submission cannot be edited after the form closes', async () => {
    await service.from('forms').update({ status: 'closed' }).eq('id', forms.union);
    expect.noRows(
      await as.studentB
        .from('form_submissions')
        .update({ answers: { book: 'too late' } })
        .eq('form_id', forms.union)
        .select('id'),
      'editing a closed form'
    );
    await service.from('forms').update({ status: 'open' }).eq('id', forms.union);
  });

  // -------------------------------------------------------------------
  // Administrators
  // -------------------------------------------------------------------

  test('an active editor gets exactly their own organization', async () => {
    const created = await as.liwenEditor
      .from('forms')
      .insert({ title: `editor-made-${run}`, organization: 'liwen', created_by: users.liwenEditor })
      .select('id');
    assert.equal(created.error, null);

    const assigned = await as.liwenEditor
      .from('form_assignments')
      .insert({ form_id: created.data[0].id, student_user_id: users.studentA, assigned_by: users.liwenEditor })
      .select('id');
    assert.equal(assigned.error, null);

    const audit = await as.liwenEditor.from('audit_log').select('id');
    assert.ok(audit.data.length >= 1, 'and can read their own organization audit trail');
  });

  test('an editor cannot forge the assignment actor', async () => {
    expect.rls(
      await as.liwenEditor.from('form_assignments').insert({
        form_id: forms.unassigned,
        student_user_id: users.studentA,
        assigned_by: users.liwenOwner,
      }),
      'assigned_by must be the acting admin'
    );
  });

  test('an editor cannot create or change administrators', async () => {
    expect.rls(
      await as.liwenEditor.from('admin_users').insert({
        user_id: users.nobody,
        organization: 'liwen',
        display_name: 'smuggled in',
        role: 'editor',
      }),
      'editor creating an admin'
    );

    expect.noRows(
      await as.liwenEditor.from('admin_users').update({ role: 'owner' }).eq('user_id', users.liwenEditor).select('role'),
      'editor promoting themselves'
    );

    const { data } = await service.from('admin_users').select('role').eq('user_id', users.liwenEditor).single();
    assert.equal(data.role, 'editor');
  });

  test('an administrator user_id is immutable', async () => {
    expect.guard(
      await as.liwenOwner.from('admin_users').update({ user_id: users.nobody }).eq('user_id', users.liwenEditor),
      'rewriting user_id'
    );

    // The exact reviewer attack: rewrite the subject and the privileges in one
    // statement, so the self-check never sees itself.
    expect.guard(
      await as.liwenOwner
        .from('admin_users')
        .update({ user_id: users.nobody, role: 'owner', is_active: true })
        .eq('user_id', users.liwenOwner),
      'rewriting user_id and role together'
    );

    const { data } = await service.from('admin_users').select('user_id').eq('user_id', users.nobody);
    assert.deepEqual(data, [], 'no administrator row may appear for the target account');
  });

  test('nobody edits their own role or activation state', async () => {
    expect.guard(
      await as.liwenOwner.from('admin_users').update({ role: 'editor' }).eq('user_id', users.liwenOwner),
      'self demotion'
    );
    expect.guard(
      await as.liwenOwner.from('admin_users').update({ is_active: false }).eq('user_id', users.liwenOwner),
      'self deactivation'
    );
  });

  test('UPSERT does not bypass the guard', async () => {
    expect.guard(
      await as.liwenOwner.from('admin_users').upsert({
        user_id: users.liwenOwner,
        organization: 'liwen',
        display_name: 'Liwen Owner',
        role: 'editor',
        is_active: true,
      }),
      'self demotion by upsert'
    );

    const { data } = await service.from('admin_users').select('role').eq('user_id', users.liwenOwner).single();
    assert.equal(data.role, 'owner');
  });

  test('an owner administers only their own organization', async () => {
    expect.rls(
      await as.liwenOwner.from('admin_users').insert({
        user_id: users.nobody,
        organization: 'student_union',
        display_name: 'planted',
        role: 'owner',
      }),
      'creating an admin in the other organization'
    );

    expect.noRows(
      await as.liwenOwner.from('admin_users').update({ is_active: false }).eq('user_id', users.suEditor).select('user_id'),
      'disabling the other organization admin'
    );

    expect.guard(
      await as.liwenOwner.from('admin_users').update({ organization: 'student_union' }).eq('user_id', users.liwenEditor),
      'moving an admin between organizations'
    );

    const added = await as.liwenOwner
      .from('admin_users')
      .insert({ user_id: users.nobody, organization: 'liwen', display_name: 'New Staff', role: 'editor' })
      .select('user_id');
    assert.equal(added.error, null, 'but their own organization works normally');
    await service.from('admin_users').delete().eq('user_id', users.nobody);
  });

  test('an inactive administrator loses database access', async () => {
    expect.noRows(await as.retiredAdmin.from('forms').select('id'), 'forms');
    expect.noRows(await as.retiredAdmin.from('form_submissions').select('id'), 'submissions');
    expect.noRows(await as.retiredAdmin.from('audit_log').select('id'), 'audit_log');
    expect.noRows(await as.retiredAdmin.from('student_profiles').select('user_id'), 'student_profiles');

    expect.rls(
      await as.retiredAdmin
        .from('forms')
        .insert({ title: `zombie-${run}`, organization: 'liwen', created_by: users.retiredAdmin }),
      'creating a form'
    );
    expect.guard(
      await as.retiredAdmin.rpc('lookup_student_for_assignment', { p_email: tag('studentA') }),
      'using the lookup RPC'
    );
  });

  // -------------------------------------------------------------------
  // Privileged operations
  // -------------------------------------------------------------------

  test('student suspension is restricted to Student Union owners', async () => {
    for (const actor of ['liwenOwner', 'liwenEditor', 'suEditor', 'studentA']) {
      expect.guard(
        await as[actor].rpc('set_student_active', { p_student_user_id: users.studentA, p_active: false }),
        `${actor} suspending a student`
      );
    }
  });

  test('a Student Union owner can suspend and reactivate, and it is audited', async () => {
    const suspended = await as.suOwner.rpc('set_student_active', {
      p_student_user_id: users.studentA,
      p_active: false,
      p_reason: 'graduated',
    });
    assert.equal(suspended.error, null);

    const { data: profile } = await service
      .from('student_profiles')
      .select('is_active')
      .eq('user_id', users.studentA)
      .single();
    assert.equal(profile.is_active, false);

    const { data: entries } = await service
      .from('audit_log')
      .select('actor_user_id, action, organization, metadata')
      .eq('target_id', users.studentA)
      .order('created_at', { ascending: false })
      .limit(1);
    assert.equal(entries[0].action, 'student.suspended');
    assert.equal(entries[0].actor_user_id, users.suOwner);
    assert.equal(entries[0].organization, 'student_union');
    assert.equal(entries[0].metadata.reason, 'graduated');

    // Suspension is enforced by the database, not by the router.
    expect.noRows(await as.studentA.from('forms').select('id'), 'a suspended student sees no forms');

    const restored = await as.suOwner.rpc('set_student_active', {
      p_student_user_id: users.studentA,
      p_active: true,
    });
    assert.equal(restored.error, null);
  });

  test('the verification RPC is unreachable from a browser session', async () => {
    for (const actor of ['studentA', 'liwenOwner', 'suOwner']) {
      const result = await as[actor].rpc('record_student_verification', {
        p_user_id: users[actor],
        p_email: tag(actor),
        p_google_sub: `forged-${run}`,
      });
      assert.ok(
        denied.privilege(result.error) || result.error?.code === 'PGRST202',
        `${actor}: expected EXECUTE to be missing, got ${describeResult(result)}`
      );
    }
  });

  test('an anonymous caller cannot execute any privileged RPC', async () => {
    const client = anonymous();
    const calls = [
      ['record_student_verification', { p_user_id: users.studentA, p_email: tag('studentA'), p_google_sub: `anon-${run}` }],
      ['lookup_student_for_assignment', { p_email: tag('studentA') }],
      ['set_student_active', { p_student_user_id: users.studentA, p_active: false, p_reason: 'forged' }],
    ];
    for (const [fn, args] of calls) {
      expect.privilege(await client.rpc(fn, args), `${fn} anonymous execution`);
    }
    const profile = await service.from('student_profiles').select('is_active').eq('user_id', users.studentA).single();
    assert.equal(profile.data?.is_active, true, 'anonymous RPC attempts leave no state change');
  });

  test('the verification RPC binds one Google subject to one account', async () => {
    const created = await service.rpc('record_student_verification', {
      p_user_id: users.nobody,
      p_email: tag('nobody'),
      p_google_sub: `sub-${run}-nobody`,
    });
    assert.equal(created.error, null);

    const stolen = await service.rpc('record_student_verification', {
      p_user_id: users.nobody,
      p_email: tag('nobody'),
      p_google_sub: `sub-${run}-studentA`,
    });
    assert.ok(stolen.error, 'a subject already bound elsewhere must be refused');
    assert.match(stolen.error.message, /already bound/);
  });

  // -------------------------------------------------------------------
  // Everyone else
  // -------------------------------------------------------------------

  test('an authenticated user with no authorization record sees nothing', async () => {
    for (const table of ['forms', 'form_assignments', 'form_submissions', 'admin_users', 'audit_log']) {
      expect.noRows(await as.nobody.from(table).select('*'), table);
    }
  });

  test('the anonymous role holds no privilege at all', async () => {
    const client = anonymous();
    for (const table of ['forms', 'student_profiles', 'admin_users', 'form_assignments', 'form_submissions', 'audit_log']) {
      expect.privilege(await client.from(table).select('*'), `${table} select`);
      expect.privilege(await client.from(table).delete().neq('created_at', '1970-01-01'), `${table} delete`);
    }
    expect.privilege(
      await client.from('forms').insert({ title: 'anon', organization: 'liwen' }),
      'anonymous insert'
    );
  });

  test('the audit log is append-only from every client', async () => {
    for (const actor of ['liwenOwner', 'suOwner', 'studentA']) {
      expect.privilege(
        await as[actor].from('audit_log').insert({ action: 'forged', target_type: 'forms' }),
        `${actor} inserting audit rows`
      );
      expect.privilege(
        await as[actor].from('audit_log').update({ action: 'rewritten' }).neq('id', 0),
        `${actor} updating audit rows`
      );
      expect.privilege(await as[actor].from('audit_log').delete().neq('id', 0), `${actor} deleting audit rows`);
    }
  });

  test('form authorship survives an administrator edit', async () => {
    expect.guard(
      await as.liwenEditor.from('forms').update({ created_by: users.liwenOwner }).eq('id', forms.assigned),
      'rewriting created_by'
    );

    const { data } = await service.from('forms').select('created_by').eq('id', forms.assigned).single();
    assert.equal(data.created_by, users.liwenEditor);
  });
});
