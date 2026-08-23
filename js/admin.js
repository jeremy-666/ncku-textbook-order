// Administrator dashboard.
//
// Every control here is also enforced in the database: an editor who unhides
// the administrators section gets a policy violation, not a new admin.
//
// Administrators are organization-scoped. This page never offers a choice of
// organization - it acts as the one on the signed-in admin_users row - and the
// database would refuse anything else regardless of what the page sent.

import { supabase } from './auth.js';
import { protectPage, wireSignOut } from './guard.js';
import { codeForError, messageFor } from './messages.js';

const state = await protectPage('admin');
wireSignOut();

const db = supabase();
const isOwner = state.admin.role === 'owner';
const organization = state.admin.organization;
// Suspension is a university-wide action over student data, so it belongs to
// Student Union owners only. set_student_active() enforces this again.
const canSuspendStudents = isOwner && organization === 'student_union';

const banner = document.querySelector('#statusBanner');
const formsTable = document.querySelector('#formsTable');
const detailSection = document.querySelector('#detailSection');
const detailTitle = document.querySelector('#detailTitle');
const fieldsEditor = document.querySelector('#fieldsEditor');
const formStatus = document.querySelector('#formStatus');
const assignmentsTable = document.querySelector('#assignmentsTable');
const submissionsTable = document.querySelector('#submissionsTable');
const adminsSection = document.querySelector('#adminsSection');
const adminsTable = document.querySelector('#adminsTable');
const auditTable = document.querySelector('#auditTable');
const suspensionSection = document.querySelector('#suspensionSection');
const newFormOrganizationLabel = document.querySelector('#newFormOrganization');

const ORG_LABEL = { liwen: '麗文書局', student_union: '學生會' };

document.querySelector('#adminIdentity').textContent =
  `${state.admin.display_name}｜${ORG_LABEL[state.admin.organization]}｜${state.admin.role}`;

// Owners manage administrators. Editors never see the section - and the RLS
// policy would reject them anyway.
adminsSection.hidden = !isOwner;
suspensionSection.hidden = !canSuspendStudents;
newFormOrganizationLabel.textContent = `單位：${ORG_LABEL[organization]}`;

let selectedFormId = null;

function say(text, tone = 'error') {
  banner.textContent = text;
  banner.dataset.tone = tone;
  banner.hidden = false;
}

function fail(error) {
  say(messageFor(codeForError(error)));
  console.error(error);
}

function table(headers, rows) {
  const el = document.createElement('table');
  const thead = el.createTHead().insertRow();
  headers.forEach((header) => {
    const th = document.createElement('th');
    th.textContent = header;
    thead.appendChild(th);
  });
  const tbody = el.createTBody();
  rows.forEach((cells) => {
    const tr = tbody.insertRow();
    cells.forEach((cell) => {
      const td = tr.insertCell();
      if (cell instanceof Node) td.appendChild(cell);
      else td.textContent = cell ?? '';
    });
  });
  return el;
}

function button(label, className, onClick) {
  const el = document.createElement('button');
  el.type = 'button';
  el.className = className;
  el.textContent = label;
  el.addEventListener('click', onClick);
  return el;
}

// --- Forms ------------------------------------------------------------

const STATUS_LABEL = { draft: '準備中', open: '開放中', closed: '已截止' };

async function loadForms() {
  const { data, error } = await db
    .from('forms')
    .select('id, title, organization, status, created_at')
    .order('created_at', { ascending: false });
  formsTable.removeAttribute('aria-busy');
  formsTable.innerHTML = '';
  if (error) return fail(error);

  if (data.length === 0) {
    formsTable.textContent = '尚未建立任何表單。';
    return;
  }
  formsTable.appendChild(
    table(
      ['表單', '單位', '狀態', '建立時間', ''],
      data.map((form) => [
        form.title,
        ORG_LABEL[form.organization],
        STATUS_LABEL[form.status],
        new Date(form.created_at).toLocaleDateString('zh-TW'),
        button('管理', 'ghost-button', () => selectForm(form.id)),
      ])
    )
  );
}

document.querySelector('#createFormForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  banner.hidden = true;
  const title = document.querySelector('#newFormTitle').value.trim();
  if (!title) return;
  const { error } = await db.from('forms').insert({
    title,
    organization,
    created_by: state.session.user.id,
  });
  if (error) return fail(error);
  document.querySelector('#newFormTitle').value = '';
  say('表單已建立。', 'success');
  loadForms();
});

async function selectForm(formId) {
  selectedFormId = formId;
  banner.hidden = true;

  const { data: form, error } = await db
    .from('forms')
    .select('id, title, status, fields')
    .eq('id', formId)
    .maybeSingle();
  if (error) return fail(error);
  if (!form) return;

  detailSection.hidden = false;
  detailTitle.textContent = `表單細節：${form.title}`;
  fieldsEditor.value = JSON.stringify(form.fields ?? [], null, 2);
  formStatus.value = form.status;
  detailSection.scrollIntoView({ behavior: 'smooth' });

  loadAssignments();
  loadSubmissions();
}

document.querySelector('#saveFormButton').addEventListener('click', async () => {
  banner.hidden = true;
  let fields;
  try {
    fields = JSON.parse(fieldsEditor.value || '[]');
  } catch {
    return say('題目定義不是合法的 JSON。');
  }
  if (!Array.isArray(fields) || fields.some((field) => !field?.key || !field?.label)) {
    return say('每個題目都需要 key 與 label。');
  }
  const { error } = await db.from('forms').update({ fields, status: formStatus.value }).eq('id', selectedFormId);
  if (error) return fail(error);
  say('表單已儲存。', 'success');
  loadForms();
  loadAudit();
});

// --- Assignments ------------------------------------------------------

async function loadAssignments() {
  assignmentsTable.innerHTML = '載入中…';
  const { data, error } = await db
    .from('form_assignments')
    .select('id, student_user_id, created_at')
    .eq('form_id', selectedFormId);
  if (error) return fail(error);

  const ids = data.map((row) => row.student_user_id);
  const profiles = new Map();
  if (ids.length > 0) {
    const { data: rows } = await db
      .from('student_profiles')
      .select('user_id, email, department, year')
      .in('user_id', ids);
    (rows ?? []).forEach((row) => profiles.set(row.user_id, row));
  }

  assignmentsTable.innerHTML = '';
  if (data.length === 0) {
    assignmentsTable.textContent = '尚未指派任何學生。';
    return;
  }
  assignmentsTable.appendChild(
    table(
      ['Email', '系所', '年級', ''],
      data.map((row) => {
        const profile = profiles.get(row.student_user_id);
        return [
          profile?.email ?? row.student_user_id,
          profile?.department ?? '',
          profile?.year ? `${profile.year}年級` : '',
          button('移除', 'ghost-button danger', async () => {
            const { error: deleteError } = await db.from('form_assignments').delete().eq('id', row.id);
            if (deleteError) return fail(deleteError);
            loadAssignments();
            loadAudit();
          }),
        ];
      })
    )
  );
}

document.querySelector('#assignForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  banner.hidden = true;
  if (!selectedFormId) return say('請先選擇一份表單。');

  const emailField = document.querySelector('#assignEmail');
  const email = emailField.value.trim().toLowerCase();

  // Administrators cannot read the roster; this RPC answers one exact email
  // with one user id and nothing else.
  const { data: matches, error: lookupError } = await db.rpc('lookup_student_for_assignment', { p_email: email });
  if (lookupError) return fail(lookupError);
  const profile = matches?.[0];
  if (!profile) return say('找不到這個學生，請確認他已經用 Google 帳號登入過一次。');
  if (!profile.assignable) return say('這個學生的帳號目前無法接收表單。');

  const { error } = await db
    .from('form_assignments')
    .insert({ form_id: selectedFormId, student_user_id: profile.user_id, assigned_by: state.session.user.id });
  if (error && error.code === '23505') return say('這個學生已經被指派過了。', 'info');
  if (error) return fail(error);

  emailField.value = '';
  say('已指派。', 'success');
  loadAssignments();
  loadAudit();
});

// --- Submissions ------------------------------------------------------

async function loadSubmissions() {
  submissionsTable.innerHTML = '載入中…';
  const { data, error } = await db
    .from('form_submissions')
    .select('id, student_user_id, status, submitted_at, answers')
    .eq('form_id', selectedFormId)
    .order('updated_at', { ascending: false });
  if (error) return fail(error);

  const ids = [...new Set(data.map((row) => row.student_user_id))];
  const profiles = new Map();
  if (ids.length > 0) {
    const { data: rows } = await db.from('student_profiles').select('user_id, email').in('user_id', ids);
    (rows ?? []).forEach((row) => profiles.set(row.user_id, row));
  }

  submissionsTable.innerHTML = '';
  if (data.length === 0) {
    submissionsTable.textContent = '尚未有任何預訂。';
    return;
  }
  submissionsTable.appendChild(
    table(
      ['學生', '狀態', '送出時間', '內容'],
      data.map((row) => {
        const pre = document.createElement('pre');
        pre.className = 'answers';
        pre.textContent = JSON.stringify(row.answers, null, 2);
        return [
          profiles.get(row.student_user_id)?.email ?? row.student_user_id,
          row.status === 'submitted' ? '已送出' : '草稿',
          row.submitted_at ? new Date(row.submitted_at).toLocaleString('zh-TW') : '',
          pre,
        ];
      })
    )
  );
}

// --- Administrators (owner only) --------------------------------------

async function loadAdmins() {
  if (!isOwner) return;
  adminsTable.innerHTML = '載入中…';
  const { data, error } = await db
    .from('admin_users')
    .select('user_id, display_name, organization, role, is_active')
    .order('created_at');
  if (error) return fail(error);

  adminsTable.innerHTML = '';
  adminsTable.appendChild(
    table(
      ['名稱', '單位', '角色', '狀態', ''],
      data.map((admin) => {
        const self = admin.user_id === state.session.user.id;
        const actions = document.createElement('div');
        actions.className = 'button-row';
        if (!self) {
          actions.appendChild(
            button(admin.is_active ? '停用' : '啟用', 'ghost-button', async () => {
              const { error: updateError } = await db
                .from('admin_users')
                .update({ is_active: !admin.is_active })
                .eq('user_id', admin.user_id);
              if (updateError) return fail(updateError);
              loadAdmins();
              loadAudit();
            })
          );
          actions.appendChild(
            button(admin.role === 'owner' ? '降為 editor' : '升為 owner', 'ghost-button', async () => {
              const { error: updateError } = await db
                .from('admin_users')
                .update({ role: admin.role === 'owner' ? 'editor' : 'owner' })
                .eq('user_id', admin.user_id);
              if (updateError) return fail(updateError);
              loadAdmins();
              loadAudit();
            })
          );
        } else {
          const note = document.createElement('span');
          note.className = 'muted';
          note.textContent = '（本人，無法自行調整權限）';
          actions.appendChild(note);
        }
        return [
          admin.display_name,
          ORG_LABEL[admin.organization],
          admin.role,
          admin.is_active ? '啟用中' : '已停用',
          actions,
        ];
      })
    )
  );
}

document.querySelector('#addAdminForm')?.addEventListener('submit', async (event) => {
  event.preventDefault();
  banner.hidden = true;
  const { error } = await db.from('admin_users').insert({
    user_id: document.querySelector('#adminUserId').value.trim(),
    display_name: document.querySelector('#adminDisplayName').value.trim(),
    organization,
    role: document.querySelector('#adminRole').value,
  });
  if (error) return fail(error);
  document.querySelector('#adminUserId').value = '';
  document.querySelector('#adminDisplayName').value = '';
  say('管理員已新增。', 'success');
  loadAdmins();
  loadAudit();
});

// --- Student suspension (Student Union owners only) --------------------

async function setStudentActive(active) {
  banner.hidden = true;
  const emailField = document.querySelector('#suspendEmail');
  const email = emailField.value.trim().toLowerCase();
  if (!email) return emailField.focus();

  const { data: matches, error: lookupError } = await db.rpc('lookup_student_for_assignment', { p_email: email });
  if (lookupError) return fail(lookupError);
  const student = matches?.[0];
  if (!student) return say('找不到這個學生。');

  const reasonField = document.querySelector('#suspendReason');
  const { error } = await db.rpc('set_student_active', {
    p_student_user_id: student.user_id,
    p_active: active,
    p_reason: reasonField.value.trim() || null,
  });
  if (error) return fail(error);

  emailField.value = '';
  reasonField.value = '';
  say(active ? '已恢復這個學生的帳號。' : '已停用這個學生的帳號。', 'success');
  loadAudit();
}

document.querySelector('#suspensionForm')?.addEventListener('submit', (event) => {
  event.preventDefault();
  setStudentActive(false);
});

document.querySelector('#reactivateButton')?.addEventListener('click', () => setStudentActive(true));

// --- Audit ------------------------------------------------------------

async function loadAudit() {
  const { data, error } = await db
    .from('audit_log')
    .select('actor_user_id, action, target_type, target_id, created_at')
    .order('created_at', { ascending: false })
    .limit(50);
  if (error) return fail(error);

  auditTable.innerHTML = '';
  if (data.length === 0) {
    auditTable.textContent = '尚無紀錄。';
    return;
  }
  auditTable.appendChild(
    table(
      ['時間', '操作者', '動作', '對象'],
      data.map((row) => [
        new Date(row.created_at).toLocaleString('zh-TW'),
        row.actor_user_id ?? '系統',
        row.action,
        `${row.target_type}:${row.target_id ?? ''}`,
      ])
    )
  );
}

loadForms();
loadAdmins();
loadAudit();
