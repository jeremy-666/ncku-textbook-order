// Route resolution rules: who is allowed to land where.
// Pure functions, no network - these run everywhere.

import test from 'node:test';
import assert from 'node:assert/strict';
import { ROUTES, canAccessPage, isProfileComplete, resolveDestination } from '../js/routing.js';

const verifiedStudent = { ncku_verified: true, is_active: true, department: '資訊工程學系', year: 2 };
const incompleteStudent = { ncku_verified: true, is_active: true, department: null, year: null };
const suspendedStudent = { ...verifiedStudent, is_active: false };
const unverifiedStudent = { ...verifiedStudent, ncku_verified: false };

const activeEditor = { is_active: true, role: 'editor' };
const activeOwner = { is_active: true, role: 'owner' };
const inactiveAdmin = { is_active: false, role: 'editor' };

test('no session goes to the login page', () => {
  assert.deepEqual(resolveDestination({ hasSession: false }), { route: ROUTES.LOGIN, reason: 'no_session' });
});

test('verified student with a complete profile reaches selection.html', () => {
  const result = resolveDestination({ hasSession: true, profile: verifiedStudent });
  assert.equal(result.route, ROUTES.STUDENT);
  assert.equal(result.reason, 'student');
});

test('verified student without department/year is sent to onboarding', () => {
  const result = resolveDestination({ hasSession: true, profile: incompleteStudent });
  assert.equal(result.route, ROUTES.ONBOARDING);
  assert.equal(result.reason, 'profile_incomplete');
});

test('a profile missing only the year is still incomplete', () => {
  assert.equal(isProfileComplete({ department: '醫學系', year: null }), false);
  assert.equal(isProfileComplete({ department: '   ', year: 3 }), false);
  assert.equal(isProfileComplete({ department: '醫學系', year: 3 }), true);
});

test('suspended student is denied', () => {
  const result = resolveDestination({ hasSession: true, profile: suspendedStudent });
  assert.equal(result.route, null);
  assert.equal(result.reason, 'student_suspended');
});

test('unverified student is denied', () => {
  const result = resolveDestination({ hasSession: true, profile: unverifiedStudent });
  assert.equal(result.route, null);
  assert.equal(result.reason, 'not_verified');
});

test('authenticated user with no authorization record is denied', () => {
  const result = resolveDestination({ hasSession: true });
  assert.equal(result.route, null);
  assert.equal(result.reason, 'not_authorized');
});

test('active editor and owner both reach admin.html', () => {
  for (const admin of [activeEditor, activeOwner]) {
    const result = resolveDestination({ hasSession: true, admin });
    assert.equal(result.route, ROUTES.ADMIN);
    assert.equal(result.reason, 'admin');
  }
});

test('disabled administrator is denied, not merely redirected', () => {
  const result = resolveDestination({ hasSession: true, admin: inactiveAdmin });
  assert.equal(result.route, null);
  assert.equal(result.reason, 'admin_inactive');
});

test('a student cannot open admin.html', () => {
  const verdict = canAccessPage('admin', { hasSession: true, profile: verifiedStudent });
  assert.equal(verdict.allowed, false);
  assert.equal(verdict.redirectTo, ROUTES.STUDENT);
});

test('direct admin.html visit with no session lands on login', () => {
  const verdict = canAccessPage('admin', { hasSession: false });
  assert.equal(verdict.allowed, false);
  assert.equal(verdict.redirectTo, ROUTES.LOGIN);
});

test('a disabled administrator cannot open admin.html', () => {
  const verdict = canAccessPage('admin', { hasSession: true, admin: inactiveAdmin });
  assert.equal(verdict.allowed, false);
  assert.equal(verdict.redirectTo, ROUTES.LOGIN);
  assert.equal(verdict.reason, 'admin_inactive');
});

test('an administrator is not treated as a student', () => {
  const verdict = canAccessPage('student', { hasSession: true, admin: activeEditor });
  assert.equal(verdict.allowed, false);
  assert.equal(verdict.redirectTo, ROUTES.ADMIN);
});

test('a verified student may revisit onboarding to change department/year', () => {
  assert.equal(canAccessPage('onboarding', { hasSession: true, profile: verifiedStudent }).allowed, true);
  assert.equal(canAccessPage('onboarding', { hasSession: true, profile: incompleteStudent }).allowed, true);
  assert.equal(canAccessPage('onboarding', { hasSession: true, profile: suspendedStudent }).allowed, false);
});

test('an admin_users row wins over a student profile', () => {
  // Belt and braces: if an account somehow has both, admin routing applies
  // and the student pages stay closed to it.
  const state = { hasSession: true, admin: activeOwner, profile: verifiedStudent };
  assert.equal(resolveDestination(state).route, ROUTES.ADMIN);
  assert.equal(canAccessPage('student', state).allowed, false);
});
