// Where an authenticated user is allowed to go.
//
// Pure functions over the authorization rows fetched from the database, so
// the rules are unit-testable without a browser or a network. This decides
// navigation only - it is UX, not security. The database enforces the same
// rules again through RLS for every single read and write.

export const ROUTES = {
  LOGIN: 'index.html',
  ONBOARDING: 'onboarding.html',
  STUDENT: 'selection.html',
  ADMIN: 'admin.html',
};

/**
 * @param {object} state
 * @param {boolean} state.hasSession
 * @param {{is_active: boolean, role: string}|null} [state.admin]     admin_users row, or null
 * @param {object|null} [state.profile]                               student_profiles row, or null
 * @returns {{route: string|null, reason: string}} route === null means "deny"
 */
export function resolveDestination({ hasSession, admin = null, profile = null }) {
  if (!hasSession) return { route: ROUTES.LOGIN, reason: 'no_session' };

  // Administrators are resolved first: an admin_users row is the only thing
  // that grants admin access, and it never comes from the sign-in method.
  if (admin) {
    if (!admin.is_active) return { route: null, reason: 'admin_inactive' };
    return { route: ROUTES.ADMIN, reason: 'admin' };
  }

  if (profile) {
    if (!profile.ncku_verified) return { route: null, reason: 'not_verified' };
    if (!profile.is_active) return { route: null, reason: 'student_suspended' };
    if (!isProfileComplete(profile)) return { route: ROUTES.ONBOARDING, reason: 'profile_incomplete' };
    return { route: ROUTES.STUDENT, reason: 'student' };
  }

  // Authenticated by Supabase, but no authorization record anywhere.
  return { route: null, reason: 'not_authorized' };
}

export function isProfileComplete(profile) {
  return Boolean(profile && typeof profile.department === 'string' && profile.department.trim() && profile.year);
}

/**
 * Can this state stay on the page it is currently looking at?
 * @param {'admin'|'student'|'onboarding'} pageRequirement
 */
export function canAccessPage(pageRequirement, state) {
  const { route, reason } = resolveDestination(state);
  if (route === null) return { allowed: false, redirectTo: ROUTES.LOGIN, reason };

  if (pageRequirement === 'admin') {
    return reason === 'admin' ? { allowed: true, reason } : { allowed: false, redirectTo: route, reason };
  }
  if (pageRequirement === 'student') {
    return reason === 'student' ? { allowed: true, reason } : { allowed: false, redirectTo: route, reason };
  }
  if (pageRequirement === 'onboarding') {
    // A verified student may revisit onboarding to change department/year.
    return reason === 'profile_incomplete' || reason === 'student'
      ? { allowed: true, reason }
      : { allowed: false, redirectTo: route, reason };
  }
  return { allowed: false, redirectTo: ROUTES.LOGIN, reason };
}
