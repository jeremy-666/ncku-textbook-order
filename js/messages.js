// User-facing messages.
//
// Supabase exceptions and stack traces never reach the screen: every failure
// is mapped to one of these strings. Messages are deliberately vague about
// whether an account exists, and an inactive administrator is told the same
// thing as a non-administrator.

const MESSAGES = {
  // Google / student
  wrong_domain: '此系統僅開放成大 gs.ncku.edu.tw 帳號使用。',
  invalid_token: '此系統僅開放成大 gs.ncku.edu.tw 帳號使用。',
  identity_mismatch: '此系統僅開放成大 gs.ncku.edu.tw 帳號使用。',
  not_verified: '此系統僅開放成大 gs.ncku.edu.tw 帳號使用。',
  google_unavailable: '目前無法連線至 Google 登入服務，請稍後再試。',
  student_suspended: '此帳號目前已停用，請聯絡成大學生會。',

  // Administrator
  invalid_credentials: 'Email 或密碼錯誤。',
  not_authorized: '此帳號沒有管理員權限。',
  admin_inactive: '此帳號沒有管理員權限。',

  // Session / transport
  no_session: '登入狀態已失效，請重新登入。',
  session_expired: '登入狀態已失效，請重新登入。',
  network_error: '網路連線異常，請檢查網路後再試一次。',
  rate_limited: '嘗試次數過多，請稍後再試。',

  // Password reset
  reset_sent: '若這個 Email 有對應的帳號，我們已寄出重設密碼的信件。',
  reset_link_invalid: '重設密碼連結已失效，請重新申請一次。',
  reset_not_recovery: '請從「重設密碼」信件中的連結開啟這個頁面；直接開啟無法變更密碼。',
  password_too_short: '密碼長度至少需要 8 個字元。',
  password_mismatch: '兩次輸入的密碼不一致。',
  password_updated: '密碼已更新，請使用新密碼登入。',

  // Configuration / catch-all
  server_misconfigured: '系統設定尚未完成，請聯絡管理員。',
  origin_not_allowed: '系統設定尚未完成，請聯絡管理員。',
  not_configured: '系統尚未完成 Supabase 設定，請聯絡管理員。',
  unknown: '發生未預期的錯誤，請稍後再試。',
};

export function messageFor(code) {
  return MESSAGES[code] ?? MESSAGES.unknown;
}

/** Reduce anything Supabase or fetch can throw to one of our codes. */
export function codeForError(error) {
  if (!error) return 'unknown';
  if (error.code && MESSAGES[error.code]) return error.code;

  const status = error.status ?? error.originalError?.status;
  const raw = `${error.message ?? ''}`.toLowerCase();

  if (raw.includes('failed to fetch') || raw.includes('networkerror') || error.name === 'TypeError') {
    return 'network_error';
  }
  if (status === 429 || raw.includes('rate limit')) return 'rate_limited';
  if (raw.includes('invalid login credentials') || raw.includes('invalid credentials')) return 'invalid_credentials';
  if (raw.includes('email not confirmed')) return 'invalid_credentials';
  if (status === 401 || raw.includes('jwt expired') || raw.includes('session')) return 'session_expired';
  return 'unknown';
}
