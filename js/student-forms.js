// The student's home page: the forms assigned to them.
//
// This query has no `where student_user_id = me` clause and does not need
// one. forms_select_assigned makes an unassigned form simply not exist for
// this user, so "select * from forms" already returns exactly their forms.

import { supabase } from './auth.js';
import { protectPage, wireSignOut } from './guard.js';
import { codeForError, messageFor } from './messages.js';

const state = await protectPage('student');
wireSignOut();

const banner = document.querySelector('#statusBanner');
const list = document.querySelector('#formList');

document.querySelector('#profileLine').textContent =
  `${state.profile.email}｜${state.profile.department} ${state.profile.year}年級`;

function showStatus(code) {
  banner.textContent = messageFor(code);
  banner.dataset.tone = 'error';
  banner.hidden = false;
}

const STATUS_LABEL = { open: '開放中', closed: '已截止', draft: '準備中' };
const SUBMISSION_LABEL = { submitted: '已送出', draft: '尚未送出' };

function card(form, submission) {
  const article = document.createElement('article');
  article.className = 'form-card';

  const heading = document.createElement('h3');
  heading.textContent = form.title;
  article.appendChild(heading);

  if (form.description) {
    const description = document.createElement('p');
    description.className = 'muted';
    description.textContent = form.description;
    article.appendChild(description);
  }

  const meta = document.createElement('p');
  meta.className = 'form-meta';
  const openLabel = STATUS_LABEL[form.status] ?? form.status;
  const subLabel = submission ? SUBMISSION_LABEL[submission.status] : '尚未填寫';
  meta.innerHTML = '';
  const statusTag = document.createElement('span');
  statusTag.className = `tag tag-${form.status}`;
  statusTag.textContent = openLabel;
  const subTag = document.createElement('span');
  subTag.className = `tag ${submission?.status === 'submitted' ? 'tag-done' : 'tag-todo'}`;
  subTag.textContent = subLabel;
  meta.append(statusTag, subTag);
  if (form.closes_at) {
    const closes = document.createElement('span');
    closes.className = 'muted';
    closes.textContent = `截止：${new Date(form.closes_at).toLocaleString('zh-TW')}`;
    meta.appendChild(closes);
  }
  article.appendChild(meta);

  const link = document.createElement('a');
  link.className = 'primary-button continue-button';
  link.href = `form.html?form=${encodeURIComponent(form.id)}`;
  link.textContent = form.status === 'open' ? '填寫預訂單 →' : '查看內容';
  article.appendChild(link);

  return article;
}

async function render() {
  const db = supabase();
  const [formsResult, submissionsResult] = await Promise.all([
    db.from('forms').select('id, title, description, status, opens_at, closes_at').order('created_at', { ascending: false }),
    db.from('form_submissions').select('form_id, status'),
  ]);

  if (formsResult.error) {
    list.innerHTML = '';
    list.removeAttribute('aria-busy');
    showStatus(codeForError(formsResult.error));
    return;
  }

  const submissions = new Map((submissionsResult.data ?? []).map((row) => [row.form_id, row]));
  list.innerHTML = '';
  list.removeAttribute('aria-busy');

  if (formsResult.data.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'form-placeholder';
    empty.innerHTML = '<div class="placeholder-icon" aria-hidden="true">▤</div><h3>目前沒有指派給你的表單</h3>';
    const note = document.createElement('p');
    note.textContent = '當學生會或麗文書局開放你的系所預訂時，表單會出現在這裡。';
    empty.appendChild(note);
    list.appendChild(empty);
    return;
  }

  formsResult.data.forEach((form) => list.appendChild(card(form, submissions.get(form.id))));
}

render();
