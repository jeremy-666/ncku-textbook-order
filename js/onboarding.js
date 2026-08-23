// Department / year onboarding.
//
// department and year are the only student_profiles columns the authenticated
// role holds an UPDATE grant on, so this page physically cannot touch
// ncku_verified or is_active even if the request is rewritten by hand.

import { supabase } from './auth.js';
import { protectPage, wireSignOut } from './guard.js';
import { ROUTES } from './routing.js';
import { codeForError, messageFor } from './messages.js';
import { departmentNames, yearsFor } from './departments.js';

const state = await protectPage('onboarding');
wireSignOut();

const banner = document.querySelector('#statusBanner');
const form = document.querySelector('#profileForm');
const departmentInput = document.querySelector('#department');
const departmentList = document.querySelector('#departmentList');
const gradeSelect = document.querySelector('#grade');
const saveButton = document.querySelector('#saveButton');

document.querySelector('#accountLine').textContent = `登入帳號：${state.profile?.email ?? ''}`;

function showStatus(code, tone = 'error') {
  banner.textContent = messageFor(code);
  banner.dataset.tone = tone;
  banner.hidden = false;
}

function populateDepartments() {
  departmentList.innerHTML = '';
  departmentNames.forEach((department) => {
    const option = document.createElement('option');
    option.value = department;
    departmentList.appendChild(option);
  });
}

function populateGrades() {
  const years = yearsFor(departmentInput.value);
  const priorValue = gradeSelect.value;
  gradeSelect.innerHTML = '<option value="" selected disabled>請選擇年級</option>';
  for (let year = 1; year <= years; year += 1) {
    const option = document.createElement('option');
    option.value = String(year);
    option.textContent = `${year}年級`;
    gradeSelect.appendChild(option);
  }
  if ([...gradeSelect.options].some((option) => option.value === priorValue)) {
    gradeSelect.value = priorValue;
  }
}

departmentInput.addEventListener('input', populateGrades);
departmentInput.addEventListener('change', populateGrades);

populateDepartments();
if (state.profile?.department) departmentInput.value = state.profile.department;
populateGrades();
if (state.profile?.year) gradeSelect.value = String(state.profile.year);

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  banner.hidden = true;

  const department = departmentInput.value.trim();
  const year = Number.parseInt(gradeSelect.value, 10);

  if (!departmentNames.includes(department)) {
    banner.textContent = '請從清單中選擇你的系所。';
    banner.dataset.tone = 'error';
    banner.hidden = false;
    departmentInput.focus();
    return;
  }
  if (!Number.isInteger(year) || year < 1 || year > yearsFor(department)) {
    banner.textContent = '請選擇你的年級。';
    banner.dataset.tone = 'error';
    banner.hidden = false;
    gradeSelect.focus();
    return;
  }

  saveButton.disabled = true;
  saveButton.textContent = '儲存中…';

  const { error } = await supabase()
    .from('student_profiles')
    .update({ department, year })
    .eq('user_id', state.session.user.id);

  if (error) {
    showStatus(codeForError(error));
    saveButton.disabled = false;
    saveButton.textContent = '儲存並繼續 →';
    return;
  }

  window.location.replace(ROUTES.STUDENT);
});
