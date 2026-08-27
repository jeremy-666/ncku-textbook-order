// Navigation policy for an authenticated NCKU Google user.
export const ROUTES = {
  LOGIN: 'index.html',
  ONBOARDING: 'onboarding.html',
  STUDENT: 'selection.html',
  ADMIN: 'admin.html',
};

/**
 * @param {object} state
 * @param {boolean} state.hasSession
 * @param {{is_active: boolean, role: string}|null} [state.admin]
 * @param {object|null} [state.profile]
 * @returns {{route: string|null, reason: string}}
 */
export function resolveDestination({ hasSession, admin = null, profile = null }) {
  if (!hasSession) return { route: ROUTES.LOGIN, reason: 'no_session' };

  if (admin) {
    if (!admin.is_active) return { route: null, reason: 'admin_inactive' };
    return { route: ROUTES.ADMIN, reason: 'admin' };
  }

  // A valid NCKU Google session is allowed to reach onboarding immediately.
  // The database trigger creates its profile record; an incomplete record
  // remains on this page until department and year have been saved.
  if (!profile || !isProfileComplete(profile)) {
    return { route: ROUTES.ONBOARDING, reason: 'profile_incomplete' };
  }

  if (!profile.ncku_verified) return { route: null, reason: 'not_verified' };
  if (!profile.is_active) return { route: null, reason: 'student_suspended' };
  return { route: ROUTES.STUDENT, reason: 'student' };
}

export function isProfileComplete(profile) {
  return Boolean(
    profile
      && typeof profile.department === 'string'
      && profile.department.trim()
      && profile.year,
  );
}

export function canAccessPage(pageRequirement, state) {
  const { route, reason } = resolveDestination(state);

  if (route === null) {
    return { allowed: false, redirectTo: ROUTES.LOGIN, reason };
  }

  if (pageRequirement === 'admin') {
    return reason === 'admin'
      ? { allowed: true, reason }
      : { allowed: false, redirectTo: route, reason };
  }

  if (pageRequirement === 'student') {
    return reason === 'student'
      ? { allowed: true, reason }
      : { allowed: false, redirectTo: route, reason };
  }

  if (pageRequirement === 'onboarding') {
    return reason === 'profile_incomplete' || reason === 'student'
      ? { allowed: true, reason }
      : { allowed: false, redirectTo: route, reason };
  }

  return { allowed: false, redirectTo: ROUTES.LOGIN, reason };
}
