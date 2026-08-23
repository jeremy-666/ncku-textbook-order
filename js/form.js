// Fill in one assigned form.
//
// The form id arrives in the query string, which is untrusted input and is
// treated as such: if the student is not assigned to it, the select simply
// returns no row. The query string can name any uuid it likes.

import { supabase } from './auth.js';
import { protectPage, wireSignOut } from './guard.js';
import { codeForError, messageFor } from './messages.js';

const state = await protectPage('student');
wireSignOut();

const banner = document.querySelector('#statusBanner');
const titleEl = document.querySelector('#formTitle');
const descriptionEl = document.querySelector('#formDescription');
const orderForm = document.querySelector('#orderForm');
const fieldContainer = document.querySelector('#fieldContainer');
const saveDraftButton = document.querySelector('#saveDraftButton');
const submitButton = document.querySelector('#submitButton');

const formId = new URLSearchParams(window.location.search).get('form');

function showStatus(text, tone = 'error') {
  banner.textContent = text;
  banner.dataset.tone = tone;
  banner.hidden = false;
}

function notAvailable() {
  titleEl.textContent = '找不到這份表單';
  descriptionEl.textContent = '這份表單不存在，或者沒有指派給你。';
  orderForm.hidden = true;
}

function buildField(field, value) {
  const wrapper = document.createElement('div');
  wrapper.className = 'field-block';

  const label = document.createElement('label');
  label.setAttribute('for', `field-${field.key}`);
  label.textContent = field.required ? `${field.label} *` : field.label;
  wrapper.appendChild(label);

  let input;
  if (field.type === 'textarea') {
    input = document.createElement('textarea');
    input.rows = 3;
    input.value = value ?? '';
  } else if (field.type === 'select') {
    input = document.createElement('select');
    const blank = document.createElement('option');
    blank.value = '';
    blank.textContent = '請選擇';
    input.appendChild(blank);
    (field.options ?? []).forEach((option) => {
      const el = document.createElement('option');
      el.value = option;
      el.textContent = option;
      input.appendChild(el);
    });
    input.value = value ?? '';
  } else if (field.type === 'checkbox') {
    input = document.createElement('input');
    input.type = 'checkbox';
    input.checked = Boolean(value);
    wrapper.classList.add('field-inline');
  } else {
    input = document.createElement('input');
    input.type = field.type === 'number' ? 'number' : 'text';
    input.value = value ?? '';
  }

  input.id = `field-${field.key}`;
  input.name = field.key;
  input.dataset.fieldType = field.type ?? 'text';
  if (field.required) input.dataset.required = 'true';
  wrapper.appendChild(input);

  if (field.hint) {
    const hint = document.createElement('p');
    hint.className = 'hint';
    hint.textContent = field.hint;
    wrapper.appendChild(hint);
  }
  return wrapper;
}

function readAnswers() {
  const answers = {};
  fieldContainer.querySelectorAll('[data-field-type]').forEach((input) => {
    if (input.dataset.fieldType === 'checkbox') answers[input.name] = input.checked;
    else if (input.dataset.fieldType === 'number') answers[input.name] = input.value === '' ? null : Number(input.value);
    else answers[input.name] = input.value;
  });
  return answers;
}

function firstMissingRequired() {
  for (const input of fieldContainer.querySelectorAll('[data-required="true"]')) {
    const empty = input.dataset.fieldType === 'checkbox' ? !input.checked : `${input.value}`.trim() === '';
    if (empty) return input;
  }
  return null;
}

let currentForm = null;
let currentSubmission = null;

async function save(status) {
  // submitted_at and created_at are stamped by the database from `status`;
  // a browser clock is not evidence of when an order was placed.
  const payload = {
    form_id: currentForm.id,
    student_user_id: state.session.user.id,
    answers: readAnswers(),
    status,
  };

  const db = supabase();
  const { data, error } = currentSubmission
    ? await db
        .from('form_submissions')
        .update({ answers: payload.answers, status })
        .eq('id', currentSubmission.id)
        .select('id, status')
        .maybeSingle()
    : await db.from('form_submissions').insert(payload).select('id, status').maybeSingle();

  if (error) throw error;
  if (!data) {
    // RLS accepted no row: the form stopped accepting submissions.
    throw Object.assign(new Error('form closed'), { code: 'form_closed' });
  }
  currentSubmission = data;
  return data;
}

function withBusy(button, label, action) {
  return async () => {
    banner.hidden = true;
    const original = button.textContent;
    button.disabled = true;
    saveDraftButton.disabled = true;
    submitButton.disabled = true;
    button.textContent = label;
    try {
      await action();
    } catch (error) {
      showStatus(error.code === 'form_closed' ? '這份表單已經截止，無法再修改。' : messageFor(codeForError(error)));
    } finally {
      button.textContent = original;
      button.disabled = false;
      saveDraftButton.disabled = false;
      submitButton.disabled = false;
    }
  };
}

saveDraftButton.addEventListener(
  'click',
  withBusy(saveDraftButton, '儲存中…', async () => {
    await save('draft');
    showStatus('草稿已儲存。', 'info');
  })
);

orderForm.addEventListener('submit', (event) => {
  event.preventDefault();
  const missing = firstMissingRequired();
  if (missing) {
    showStatus('請填寫所有必填欄位。');
    missing.focus();
    return;
  }
  withBusy(submitButton, '送出中…', async () => {
    await save('submitted');
    showStatus('預訂已送出，謝謝你！', 'success');
  })();
});

async function load() {
  if (!formId) return notAvailable();

  const db = supabase();
  const { data: form, error } = await db
    .from('forms')
    .select('id, title, description, status, fields, closes_at')
    .eq('id', formId)
    .maybeSingle();

  if (error) {
    if (error.code === '22P02') return notAvailable(); // not even a uuid
    showStatus(messageFor(codeForError(error)));
    return;
  }
  if (!form) return notAvailable();

  currentForm = form;
  titleEl.textContent = form.title;
  descriptionEl.textContent = form.description ?? '';

  const { data: submission } = await db
    .from('form_submissions')
    .select('id, status, answers')
    .eq('form_id', form.id)
    .maybeSingle();
  currentSubmission = submission ?? null;

  const answers = submission?.answers ?? {};
  const fields = Array.isArray(form.fields) ? form.fields : [];
  if (fields.length === 0) {
    fieldContainer.innerHTML =
      '<div class="form-placeholder"><div class="placeholder-icon" aria-hidden="true">▤</div><h3>這份表單還沒有題目</h3><p>管理員尚未加入預訂欄位。</p></div>';
  } else {
    fields.forEach((field) => fieldContainer.appendChild(buildField(field, answers[field.key])));
  }

  orderForm.hidden = false;

  const closed = form.status !== 'open' || (form.closes_at && new Date(form.closes_at) <= new Date());
  if (closed) {
    fieldContainer.querySelectorAll('input, select, textarea').forEach((input) => (input.disabled = true));
    saveDraftButton.disabled = true;
    submitButton.disabled = true;
    showStatus('這份表單目前沒有開放填寫。', 'info');
  } else if (submission?.status === 'submitted') {
    showStatus('你已經送出這份預訂，仍可在截止前修改。', 'info');
  }
}

load();
