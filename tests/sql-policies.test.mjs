// Database authorization, executed against a real PostgreSQL.
//
// This is the tier that proves the SQL *runs* and that the policies decide the
// way the design claims. It runs everywhere, with no credentials, because
// PGlite is a disposable in-process PostgreSQL - see tests/support/pg-harness.mjs.
//
// What it cannot prove: PostgREST behaviour, GoTrue sessions, and the exact
// privileges Supabase gives its own roles. tests/rls.test.mjs covers those
// against a live scratch project.
//
// Every case runs twice: once with the migrations owned by a superuser, once
// owned by a plain role subject to FORCE ROW LEVEL SECURITY. A design that
// only works in the first mode is relying on BYPASSRLS nobody guaranteed.

import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { DENIAL, OWNER_MODES, createHarness } from './support/pg-harness.mjs';

const ADMINS = [
  ['liwenEditor', 'liwen', 'editor', true],
  ['liwenOwner', 'liwen', 'owner', true],
  ['suEditor', 'student_union', 'editor', true],
  ['suOwner', 'student_union', 'owner', true],
  ['retiredAdmin', 'liwen', 'editor', false],
];

for (const ownerMode of OWNER_MODES) {
  describe(`policies (migrations owned by a ${ownerMode} role)`, () => {
    let h;
    const forms = {};

    before(async () => {
      h = await createHarness({ ownerMode });

      for (const name of [
        'studentA', 'studentB', 'studentSuspended', 'nobody',
        ...ADMINS.map(([name]) => name),
      ]) {
        await h.addUser(name);
      }

      for (const [name, organization, role, isActive] of ADMINS) {
        await h.priv(
          'insert into public.admin_users (user_id, organization, display_name, role, is_active) values ($1,$2,$3,$4,$5)',
          [h.id(name), organization, name, role, isActive]
        );
      }

      for (const [name, extra] of [
        ['studentA', {}],
        ['studentB', {}],
        ['studentSuspended', { is_active: false }],
      ]) {
        await h.priv(
          `insert into public.student_profiles
             (user_id, email, google_sub, department, year, ncku_verified, verified_at, is_active)
           values ($1,$2,$3,$4,$5,true,now(),$6)`,
          [h.id(name), `${name}@gs.ncku.edu.tw`, `sub-${name}`, '資訊工程學系', 2, extra.is_active ?? true]
        );
      }

      for (const [key, organization, status] of [
        ['liwenOpen', 'liwen', 'open'],
        ['liwenDraft', 'liwen', 'draft'],
        ['liwenClosed', 'liwen', 'closed'],
        ['suOpen', 'student_union', 'open'],
      ]) {
        const [row] = await h.priv(
          `insert into public.forms (title, organization, status, created_by, description)
           values ($1,$2,$3,$4,$5) returning id`,
          [key, organization, status, h.id(organization === 'liwen' ? 'liwenEditor' : 'suEditor'), 'original']
        );
        forms[key] = row.id;
      }

      // studentA belongs to Liwen forms; studentB only ever dealt with the
      // Student Union. That split is what the profile-privacy tests turn on.
      for (const [key, student, by] of [
        ['liwenOpen', 'studentA', 'liwenEditor'],
        ['liwenDraft', 'studentA', 'liwenEditor'],
        ['liwenClosed', 'studentA', 'liwenEditor'],
        ['suOpen', 'studentB', 'suEditor'],
      ]) {
        await h.priv(
          'insert into public.form_assignments (form_id, student_user_id, assigned_by) values ($1,$2,$3)',
          [forms[key], h.id(student), h.id(by)]
        );
      }
    });

    after(async () => {
      await h?.close();
    });

    const asUser = (name, sql, params) => h.as('authenticated', h.id(name), sql, params);

    // -----------------------------------------------------------------
    // 1. Organization isolation
    // -----------------------------------------------------------------

    test('an administrator sees only their own organization forms', async () => {
      const liwen = await asUser('liwenEditor', 'select id, organization from public.forms');
      assert.equal(liwen.error, null);
      assert.equal(liwen.rows.length, 3);
      assert.ok(liwen.rows.every((row) => row.organization === 'liwen'));

      const su = await asUser('suEditor', 'select id, organization from public.forms');
      assert.deepEqual(su.rows.map((row) => row.id), [forms.suOpen]);
    });

    test('a Liwen editor cannot read, update or delete a Student Union form', async () => {
      const read = await asUser('liwenEditor', 'select id from public.forms where id = $1', [forms.suOpen]);
      assert.deepEqual(read.rows, [], 'the row must not exist for the other organization');

      const update = await asUser(
        'liwenEditor',
        'update public.forms set title = $2 where id = $1 returning id',
        [forms.suOpen, 'taken over']
      );
      assert.equal(update.error, null);
      assert.deepEqual(update.rows, [], 'USING filtered every row out; nothing was updated');

      const remove = await asUser('liwenOwner', 'delete from public.forms where id = $1 returning id', [forms.suOpen]);
      assert.equal(remove.error, null);
      assert.deepEqual(remove.rows, [], 'even an owner deletes nothing outside their organization');

      const [survivor] = await h.priv('select title from public.forms where id = $1', [forms.suOpen]);
      assert.equal(survivor.title, 'suOpen');
    });

    test('a Student Union editor cannot read, update or delete a Liwen form', async () => {
      const read = await asUser('suEditor', 'select id from public.forms where id = $1', [forms.liwenOpen]);
      assert.deepEqual(read.rows, []);

      const update = await asUser(
        'suEditor',
        'update public.forms set status = $2 where id = $1 returning id',
        [forms.liwenOpen, 'closed']
      );
      assert.deepEqual(update.rows, []);

      const remove = await asUser('suOwner', 'delete from public.forms where id = $1 returning id', [forms.liwenOpen]);
      assert.deepEqual(remove.rows, []);
    });

    test('cross-organization assignments are refused', async () => {
      const result = await asUser(
        'liwenEditor',
        'insert into public.form_assignments (form_id, student_user_id, assigned_by) values ($1,$2,$3)',
        [forms.suOpen, h.id('studentA'), h.id('liwenEditor')]
      );
      assert.ok(DENIAL.rls(result.error), `expected an RLS refusal, got ${result.error?.message}`);

      const removal = await asUser(
        'suEditor',
        'delete from public.form_assignments where form_id = $1 returning id',
        [forms.liwenOpen]
      );
      assert.deepEqual(removal.rows, [], 'and the other organization cannot un-assign either');
    });

    test('submissions are visible only to the organization that owns the form', async () => {
      await h.priv(
        `insert into public.form_submissions (form_id, student_user_id, answers, status)
         values ($1,$2,$3,'submitted') on conflict do nothing`,
        [forms.liwenOpen, h.id('studentA'), JSON.stringify({ book: 'Liwen only' })]
      );

      const liwen = await asUser('liwenEditor', 'select id, answers from public.form_submissions');
      assert.equal(liwen.rows.length, 1);

      const su = await asUser('suEditor', 'select id from public.form_submissions');
      assert.deepEqual(su.rows, [], 'the Student Union sees nothing of a Liwen order');
    });

    test('organization cannot be forged through the request payload', async () => {
      // Claiming the other organization on INSERT.
      const forgedInsert = await asUser(
        'liwenEditor',
        'insert into public.forms (title, organization, created_by) values ($1,$2,$3)',
        ['smuggled', 'student_union', h.id('liwenEditor')]
      );
      assert.ok(DENIAL.rls(forgedInsert.error), `expected an RLS refusal, got ${forgedInsert.error?.message}`);

      // Moving an existing form out of reach.
      const forgedUpdate = await asUser(
        'liwenEditor',
        'update public.forms set organization = $2 where id = $1',
        [forms.liwenOpen, 'student_union']
      );
      assert.ok(DENIAL.guard(forgedUpdate.error), `expected the guard trigger, got ${forgedUpdate.error?.message}`);
      assert.match(forgedUpdate.error.message, /organization is immutable/);
    });

    test('the audit trail is organization-scoped', async () => {
      const liwen = await asUser('liwenEditor', 'select distinct organization from public.audit_log');
      assert.deepEqual(liwen.rows.map((row) => row.organization), ['liwen']);

      const su = await asUser('suEditor', 'select distinct organization from public.audit_log');
      assert.deepEqual(su.rows.map((row) => row.organization), ['student_union']);
    });

    // -----------------------------------------------------------------
    // 2. Student profile privacy
    // -----------------------------------------------------------------

    test('an administrator sees only students assigned to their own forms', async () => {
      const liwen = await asUser('liwenEditor', 'select user_id from public.student_profiles');
      assert.deepEqual(liwen.rows.map((row) => row.user_id), [h.id('studentA')]);

      const su = await asUser('suEditor', 'select user_id from public.student_profiles');
      assert.deepEqual(su.rows.map((row) => row.user_id), [h.id('studentB')]);
    });

    test('the assignment lookup returns an id and nothing else', async () => {
      const hit = await asUser('liwenEditor', 'select * from public.lookup_student_for_assignment($1)', [
        'StudentB@gs.ncku.edu.tw',
      ]);
      assert.equal(hit.error, null);
      assert.deepEqual(hit.rows, [{ user_id: h.id('studentB'), assignable: true }]);
      assert.deepEqual(Object.keys(hit.rows[0]), ['user_id', 'assignable'], 'no department, year or email leaks');

      const miss = await asUser('liwenEditor', 'select * from public.lookup_student_for_assignment($1)', ['nope@x.test']);
      assert.deepEqual(miss.rows, []);

      const enumerate = await asUser('liwenEditor', 'select * from public.lookup_student_for_assignment($1)', ['']);
      assert.deepEqual(enumerate.rows, [], 'an empty needle is not a roster dump');

      const student = await asUser('studentA', 'select * from public.lookup_student_for_assignment($1)', [
        'studentB@gs.ncku.edu.tw',
      ]);
      assert.ok(DENIAL.guard(student.error), `students must be refused: ${student.error?.message}`);
    });

    // -----------------------------------------------------------------
    // 3. Administrator identity immutability
    // -----------------------------------------------------------------

    test('an owner cannot rewrite user_id on an administrator row', async () => {
      const result = await asUser(
        'liwenOwner',
        'update public.admin_users set user_id = $2 where user_id = $1',
        [h.id('liwenEditor'), h.id('nobody')]
      );
      assert.ok(DENIAL.guard(result.error));
      assert.match(result.error.message, /identity \(user_id\) is immutable/);
    });

    test('rewriting user_id and role in one statement does not bypass the self-check', async () => {
      // The reviewer attack: the old guard tested NEW.user_id, so an owner
      // could re-point their own row at another account while promoting it,
      // and the "you cannot change your own role" branch never ran.
      const result = await asUser(
        'liwenOwner',
        "update public.admin_users set user_id = $2, role = 'owner', is_active = true where user_id = $1",
        [h.id('liwenOwner'), h.id('nobody')]
      );
      assert.ok(DENIAL.guard(result.error), `expected the guard trigger, got ${result.error?.message}`);

      const rows = await h.priv('select user_id, role from public.admin_users where user_id = $1', [h.id('nobody')]);
      assert.deepEqual(rows, [], 'no administrator row may appear for the target account');
    });

    test('an owner cannot change their own role or activation state', async () => {
      for (const sql of [
        "update public.admin_users set role = 'editor' where user_id = $1",
        'update public.admin_users set is_active = false where user_id = $1',
      ]) {
        const result = await asUser('liwenOwner', sql, [h.id('liwenOwner')]);
        assert.ok(DENIAL.guard(result.error), `expected the guard trigger, got ${result.error?.message}`);
        assert.match(result.error.message, /cannot change their own role or activation state/);
      }
    });

    test('UPSERT does not bypass the guard', async () => {
      // ON CONFLICT DO UPDATE takes the UPDATE path, so it must meet the same
      // guard as a plain UPDATE - both for self-modification and for identity.
      const selfDemote = await asUser(
        'liwenOwner',
        `insert into public.admin_users (user_id, organization, display_name, role, is_active)
         values ($1, 'liwen', 'me', 'owner', true)
         on conflict (user_id) do update set role = 'editor'`,
        [h.id('liwenOwner')]
      );
      assert.ok(DENIAL.guard(selfDemote.error), `expected the guard trigger, got ${selfDemote.error?.message}`);

      const rewriteId = await asUser(
        'liwenOwner',
        `insert into public.admin_users (user_id, organization, display_name, role, is_active)
         values ($1, 'liwen', 'me', 'owner', true)
         on conflict (user_id) do update set user_id = $2`,
        [h.id('liwenOwner'), h.id('nobody')]
      );
      assert.ok(DENIAL.guard(rewriteId.error), `expected the guard trigger, got ${rewriteId.error?.message}`);

      const [unchanged] = await h.priv('select role, is_active from public.admin_users where user_id = $1', [
        h.id('liwenOwner'),
      ]);
      assert.deepEqual(unchanged, { role: 'owner', is_active: true });
    });

    test('an owner cannot reach into the other organization', async () => {
      const created = await asUser(
        'liwenOwner',
        "insert into public.admin_users (user_id, organization, display_name, role) values ($1,'student_union','planted','owner')",
        [h.id('nobody')]
      );
      assert.ok(DENIAL.rls(created.error), `expected an RLS refusal, got ${created.error?.message}`);

      const moved = await asUser(
        'liwenOwner',
        "update public.admin_users set organization = 'student_union' where user_id = $1",
        [h.id('liwenEditor')]
      );
      assert.ok(DENIAL.guard(moved.error));

      const foreign = await asUser(
        'liwenOwner',
        'update public.admin_users set is_active = false where user_id = $1 returning user_id',
        [h.id('suEditor')]
      );
      assert.equal(foreign.error, null);
      assert.deepEqual(foreign.rows, [], 'the other organization administrators are simply not there');
    });

    test('an owner administers their own organization normally', async () => {
      const added = await asUser(
        'liwenOwner',
        "insert into public.admin_users (user_id, organization, display_name, role) values ($1,'liwen','New Staff','editor') returning user_id",
        [h.id('nobody')]
      );
      assert.equal(added.error, null);
      assert.equal(added.rows.length, 1);

      const disabled = await asUser(
        'liwenOwner',
        'update public.admin_users set is_active = false where user_id = $1 returning is_active',
        [h.id('nobody')]
      );
      assert.equal(disabled.rows[0].is_active, false);

      await h.priv('delete from public.admin_users where user_id = $1', [h.id('nobody')]);
    });

    // -----------------------------------------------------------------
    // 4. Students cannot escalate
    // -----------------------------------------------------------------

    test('a student cannot write the columns that grant them anything', async () => {
      for (const column of ['ncku_verified', 'is_active']) {
        const result = await asUser(
          'studentA',
          `update public.student_profiles set ${column} = true where user_id = $1`,
          [h.id('studentA')]
        );
        assert.ok(
          DENIAL.privilege(result.error),
          `${column} must be refused by column privilege, got ${result.error?.message}`
        );
      }

      const identity = await asUser(
        'studentA',
        'update public.student_profiles set google_sub = $2 where user_id = $1',
        [h.id('studentA'), 'sub-studentB']
      );
      assert.ok(DENIAL.privilege(identity.error));
    });

    test('a student may still edit their own department and year', async () => {
      const result = await asUser(
        'studentA',
        'update public.student_profiles set department = $2, year = $3 where user_id = $1 returning department, year',
        [h.id('studentA'), '醫學系', 3]
      );
      assert.equal(result.error, null);
      assert.deepEqual(result.rows, [{ department: '醫學系', year: 3 }]);
    });

    test('a suspended student cannot edit even that', async () => {
      const result = await asUser(
        'studentSuspended',
        'update public.student_profiles set department = $2 where user_id = $1 returning department',
        [h.id('studentSuspended'), '醫學系']
      );
      assert.equal(result.error, null);
      assert.deepEqual(result.rows, [], 'RLS matched no row rather than raising');
    });

    test('a student cannot make themselves an administrator', async () => {
      const result = await asUser(
        'studentA',
        "insert into public.admin_users (user_id, organization, display_name, role) values ($1,'liwen','totally an admin','owner')",
        [h.id('studentA')]
      );
      assert.ok(DENIAL.rls(result.error), `expected an RLS refusal, got ${result.error?.message}`);
    });

    test('a student sees no administrators and no audit trail', async () => {
      const admins = await asUser('studentA', 'select user_id from public.admin_users');
      assert.deepEqual(admins.rows, []);
      const audit = await asUser('studentA', 'select id from public.audit_log');
      assert.deepEqual(audit.rows, []);
    });

    test('a student sees only assigned, non-draft forms', async () => {
      const visible = await asUser('studentA', 'select id from public.forms');
      assert.deepEqual(
        visible.rows.map((row) => row.id).sort(),
        [forms.liwenOpen, forms.liwenClosed].sort(),
        'the draft they are assigned to stays hidden'
      );

      const other = await asUser('studentA', 'select id from public.forms where id = $1', [forms.suOpen]);
      assert.deepEqual(other.rows, []);
    });

    test('a student cannot read another student profile or submission', async () => {
      const profiles = await asUser('studentA', 'select user_id from public.student_profiles');
      assert.deepEqual(profiles.rows.map((row) => row.user_id), [h.id('studentA')]);

      const submissions = await asUser('studentB', 'select id from public.form_submissions');
      assert.deepEqual(submissions.rows, []);
    });

    // -----------------------------------------------------------------
    // 5. Submissions
    // -----------------------------------------------------------------

    test('a submission cannot be created for someone else, or for an unassigned or closed form', async () => {
      const cases = [
        ['unassigned form', 'studentB', forms.liwenOpen, h.id('studentB')],
        ['another student', 'studentA', forms.liwenOpen, h.id('studentB')],
        ['closed form', 'studentA', forms.liwenClosed, h.id('studentA')],
        ['draft form', 'studentA', forms.liwenDraft, h.id('studentA')],
      ];
      for (const [label, actor, formId, studentId] of cases) {
        const result = await h.as(
          'authenticated',
          h.id(actor),
          'insert into public.form_submissions (form_id, student_user_id, answers) values ($1,$2,$3)',
          [formId, studentId, JSON.stringify({})]
        );
        assert.ok(DENIAL.rls(result.error), `${label}: expected an RLS refusal, got ${result.error?.message}`);
      }
    });

    test('submission identity cannot be rewritten', async () => {
      const [row] = await h.priv('select id from public.form_submissions where student_user_id = $1', [h.id('studentA')]);

      for (const [label, sql, params] of [
        ['form_id', 'update public.form_submissions set form_id = $2 where id = $1', [row.id, forms.liwenClosed]],
        ['student_user_id', 'update public.form_submissions set student_user_id = $2 where id = $1', [row.id, h.id('studentB')]],
        ['id', 'update public.form_submissions set id = gen_random_uuid() where id = $1', [row.id]],
      ]) {
        const result = await asUser('studentA', sql, params);
        assert.ok(DENIAL.guard(result.error), `${label}: expected the guard trigger, got ${result.error?.message}`);
        assert.match(result.error.message, /submission identity is immutable/);
      }
    });

    test('submission timestamps are server-controlled', async () => {
      await h.priv('delete from public.form_submissions where student_user_id = $1', [h.id('studentB')]);
      await h.priv("update public.forms set organization = organization where id = $1", [forms.suOpen]);

      const inserted = await h.as(
        'authenticated',
        h.id('studentB'),
        `insert into public.form_submissions (form_id, student_user_id, answers, status, created_at, submitted_at)
         values ($1,$2,$3,'submitted', timestamptz '2000-01-01', timestamptz '2000-01-01')
         returning created_at, submitted_at`,
        [forms.suOpen, h.id('studentB'), JSON.stringify({ book: 'x' })]
      );
      assert.equal(inserted.error, null);
      const year = (value) => new Date(value).getUTCFullYear();
      assert.ok(year(inserted.rows[0].created_at) >= 2026, 'created_at came from the server clock');
      assert.ok(year(inserted.rows[0].submitted_at) >= 2026, 'submitted_at came from the server clock');

      const backdated = await h.as(
        'authenticated',
        h.id('studentB'),
        `update public.form_submissions set submitted_at = timestamptz '2000-01-01'
         where student_user_id = $1 returning submitted_at`,
        [h.id('studentB')]
      );
      assert.ok(year(backdated.rows[0].submitted_at) >= 2026, 'and cannot be backdated afterwards');
    });

    test('a submission cannot be edited once the assignment is gone', async () => {
      const [assignment] = await h.priv(
        'select id from public.form_assignments where form_id = $1 and student_user_id = $2',
        [forms.suOpen, h.id('studentB')]
      );
      await h.priv('delete from public.form_assignments where id = $1', [assignment.id]);

      const result = await h.as(
        'authenticated',
        h.id('studentB'),
        'update public.form_submissions set answers = $2 where student_user_id = $1 returning id',
        [h.id('studentB'), JSON.stringify({ book: 'late edit' })]
      );
      assert.equal(result.error, null);
      assert.deepEqual(result.rows, [], 'USING no longer matches the row');

      await h.priv(
        'insert into public.form_assignments (form_id, student_user_id, assigned_by) values ($1,$2,$3)',
        [forms.suOpen, h.id('studentB'), h.id('suEditor')]
      );
    });

    test('a submission cannot be edited once the form closes', async () => {
      await h.priv("update public.forms set status = 'closed' where id = $1", [forms.suOpen]);
      const result = await h.as(
        'authenticated',
        h.id('studentB'),
        'update public.form_submissions set answers = $2 where student_user_id = $1 returning id',
        [h.id('studentB'), JSON.stringify({ book: 'too late' })]
      );
      assert.equal(result.error, null);
      assert.deepEqual(result.rows, []);
      await h.priv("update public.forms set status = 'open' where id = $1", [forms.suOpen]);
    });

    // -----------------------------------------------------------------
    // 6. Forms, audit and everyone else
    // -----------------------------------------------------------------

    test('form authorship cannot be rewritten', async () => {
      const result = await asUser(
        'liwenEditor',
        'update public.forms set created_by = $2 where id = $1',
        [forms.liwenOpen, h.id('liwenOwner')]
      );
      assert.ok(DENIAL.guard(result.error));
      assert.match(result.error.message, /authorship is immutable/);
    });

    test('the audit log is append-only from a client point of view', async () => {
      for (const [label, sql] of [
        ['insert', "insert into public.audit_log (action, target_type) values ('forged','forms')"],
        ['update', "update public.audit_log set action = 'rewritten'"],
        ['delete', 'delete from public.audit_log'],
      ]) {
        const result = await asUser('liwenOwner', sql);
        assert.ok(DENIAL.privilege(result.error), `${label}: expected a privilege refusal, got ${result.error?.message}`);
      }
    });

    test('NULL transitions survive in the audit metadata', async () => {
      await asUser('liwenEditor', 'update public.forms set description = null where id = $1', [forms.liwenOpen]);
      const [entry] = await h.priv(
        `select metadata from public.audit_log
         where target_id = $1 and action = 'forms.update'
         order by created_at desc, id desc limit 1`,
        [forms.liwenOpen]
      );
      assert.equal(entry.metadata.old.description, 'original');
      assert.ok('description' in entry.metadata.new, 'the key must still be present');
      assert.equal(entry.metadata.new.description, null, 'set-to-NULL is exactly the transition worth auditing');
    });

    test('a retired administrator has no access left', async () => {
      const forms_ = await asUser('retiredAdmin', 'select id from public.forms');
      assert.deepEqual(forms_.rows, []);
      const audit = await asUser('retiredAdmin', 'select id from public.audit_log');
      assert.deepEqual(audit.rows, []);
      const students = await asUser('retiredAdmin', 'select user_id from public.student_profiles');
      assert.deepEqual(students.rows, []);

      const created = await asUser(
        'retiredAdmin',
        "insert into public.forms (title, organization, created_by) values ('zombie','liwen',$1)",
        [h.id('retiredAdmin')]
      );
      assert.ok(DENIAL.rls(created.error), `expected an RLS refusal, got ${created.error?.message}`);

      const lookup = await asUser('retiredAdmin', 'select * from public.lookup_student_for_assignment($1)', [
        'studentA@gs.ncku.edu.tw',
      ]);
      assert.ok(DENIAL.guard(lookup.error), 'and cannot use the lookup RPC either');
    });

    test('an authenticated account with no authorization record sees nothing', async () => {
      for (const table of ['forms', 'form_assignments', 'form_submissions', 'admin_users', 'student_profiles', 'audit_log']) {
        const result = await asUser('nobody', `select * from public.${table}`);
        assert.equal(result.error, null, `${table} should answer, not error`);
        assert.deepEqual(result.rows, [], `${table} must be empty`);
      }
    });

    test('the anonymous role holds no privilege at all', async () => {
      for (const table of ['forms', 'student_profiles', 'admin_users', 'form_submissions', 'form_assignments', 'audit_log']) {
        const read = await h.as('anon', null, `select * from public.${table}`);
        assert.ok(DENIAL.privilege(read.error), `${table} select: got ${read.error?.message ?? 'rows'}`);

        const write = await h.as('anon', null, `delete from public.${table}`);
        assert.ok(DENIAL.privilege(write.error), `${table} delete: got ${write.error?.message ?? 'rows'}`);
      }
    });

    // -----------------------------------------------------------------
    // 7. Privileged operations
    // -----------------------------------------------------------------

    test('student suspension is restricted to Student Union owners', async () => {
      for (const actor of ['liwenOwner', 'liwenEditor', 'suEditor', 'studentA']) {
        const result = await asUser('studentA' === actor ? 'studentA' : actor,
          'select public.set_student_active($1, false, $2)', [h.id('studentA'), 'test']);
        assert.ok(
          DENIAL.guard(result.error),
          `${actor} must be refused, got ${result.error?.message ?? 'success'}`
        );
      }
    });

    test('a Student Union owner can suspend and reactivate, and it is audited', async () => {
      const suspended = await asUser('suOwner', 'select is_active from public.set_student_active($1, false, $2)', [
        h.id('studentA'),
        'graduated',
      ]);
      assert.equal(suspended.error, null);
      assert.equal(suspended.rows[0].is_active, false);

      const [entry] = await h.priv(
        `select actor_user_id, action, organization, metadata from public.audit_log
         where target_id = $1 order by created_at desc, id desc limit 1`,
        [h.id('studentA')]
      );
      assert.equal(entry.action, 'student.suspended');
      assert.equal(entry.actor_user_id, h.id('suOwner'), 'attribution is the acting owner');
      assert.equal(entry.organization, 'student_union');
      assert.equal(entry.metadata.reason, 'graduated');
      assert.equal(entry.metadata.was_active, true);

      // A suspended student loses everything immediately.
      const forms_ = await asUser('studentA', 'select id from public.forms');
      assert.deepEqual(forms_.rows, [], 'suspension takes effect in the database, not in the router');

      const restored = await asUser('suOwner', 'select is_active from public.set_student_active($1, true, null)', [
        h.id('studentA'),
      ]);
      assert.equal(restored.rows[0].is_active, true);
    });

    test('the privileged-write marker cannot be claimed by a client', async () => {
      // The definer policies are gated on a transaction-local GUC. Even if a
      // client could set it - PostgREST gives them no way to - those policies
      // apply to the migration owner, not to `authenticated`, and the column
      // grant refuses first.
      const forged = await h.asExec(
        'authenticated',
        h.id('studentA'),
        `select set_config('app.student_ctx', 'on', true);
         update public.student_profiles set is_active = true where user_id = '${h.id('studentA')}';`
      );
      assert.ok(DENIAL.privilege(forged.error), `expected a privilege refusal, got ${forged.error?.message}`);

      const admin = await h.asExec(
        'authenticated',
        h.id('liwenOwner'),
        `select set_config('app.student_ctx', 'on', true);
         update public.student_profiles set is_active = false where user_id = '${h.id('studentA')}';`
      );
      assert.ok(DENIAL.privilege(admin.error), 'and an administrator has no UPDATE privilege there either');

      const [profile] = await h.priv('select is_active from public.student_profiles where user_id = $1', [
        h.id('studentA'),
      ]);
      assert.equal(profile.is_active, true, 'nothing changed either way');
    });

    test('a student cannot reach the verification RPC at all', async () => {
      const result = await asUser('studentA', 'select public.record_student_verification($1,$2,$3)', [
        h.id('studentA'),
        'studentA@gs.ncku.edu.tw',
        'forged-sub',
      ]);
      assert.ok(DENIAL.privilege(result.error), `expected EXECUTE to be missing, got ${result.error?.message}`);
    });

    test('the verification RPC binds one Google subject to one account', async () => {
      const created = await h.as('service_role', null, 'select ncku_verified from public.record_student_verification($1,$2,$3)', [
        h.id('nobody'),
        'Nobody@gs.ncku.edu.tw',
        'sub-nobody',
      ]);
      assert.equal(created.error, null);
      assert.equal(created.rows[0].ncku_verified, true);

      const stolen = await h.as('service_role', null, 'select public.record_student_verification($1,$2,$3)', [
        h.id('nobody'),
        'nobody@gs.ncku.edu.tw',
        'sub-studentA',
      ]);
      assert.ok(DENIAL.guard(stolen.error), 'a subject already bound elsewhere is refused');
      assert.match(stolen.error.message, /already bound/);

      const [audited] = await h.priv(
        "select action, organization from public.audit_log where target_id = $1 and action like 'student.%' order by id desc limit 1",
        [h.id('nobody')]
      );
      assert.equal(audited.action, 'student.verified');
      assert.equal(audited.organization, 'student_union');

      await h.priv('delete from public.student_profiles where user_id = $1', [h.id('nobody')]);
    });

    test('re-verifying never lifts a suspension', async () => {
      await asUser('suOwner', 'select public.set_student_active($1, false, null)', [h.id('studentB')]);
      const again = await h.as('service_role', null, 'select is_active from public.record_student_verification($1,$2,$3)', [
        h.id('studentB'),
        'studentB@gs.ncku.edu.tw',
        'sub-studentB',
      ]);
      assert.equal(again.rows[0].is_active, false, 'signing in again must not reactivate a suspended account');
      await asUser('suOwner', 'select public.set_student_active($1, true, null)', [h.id('studentB')]);
    });
  });
}
