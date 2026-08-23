# Setup runbook

Everything in this repository is code. The steps below are the parts that
need your Supabase and Google Cloud consoles, and they have to be done once
before the login page works.

---

## 1. Supabase project

1. Create a project at <https://supabase.com/dashboard>.
2. **Project Settings → API** gives you:
   - Project URL → `supabaseUrl`
   - `anon` / publishable key → `supabaseAnonKey`
   - `service_role` key → **never** put this in the repo or in any deployed
     file. It belongs in your shell (`.env`) and in Supabase's own function
     secrets, nowhere else.

## 2. Google OAuth client

1. Google Cloud Console → **APIs & Services → Credentials → Create OAuth
   client ID → Web application**.
2. Authorized JavaScript origins: every origin the site is served from, e.g.
   `http://localhost:5500` and `https://your-site.netlify.app`.
3. Authorized redirect URI: `https://YOUR-PROJECT-REF.supabase.co/auth/v1/callback`.
4. Copy the **client ID** (public) and **client secret** (secret).
5. Supabase → **Authentication → Providers → Google**: enable it, paste the
   client ID and secret there.
6. Still in that provider screen, add the client ID to
   **Authorized Client IDs**. This is what lets `signInWithIdToken` accept
   tokens minted by Google Identity Services in the browser.

> Google Workspace restriction is *not* configured here. The `hd` claim is
> checked server-side in the edge function - see step 5.

## 3. Apply the migrations

With the [Supabase CLI](https://supabase.com/docs/guides/cli):

```bash
supabase link --project-ref YOUR-PROJECT-REF
supabase db push
```

Or apply **every** file in `supabase/migrations/` through the dashboard SQL
editor, in filename order. Do not omit later remediation migrations.

After running them, check **Database → Tables**: all six tables must show
"RLS enabled". If any does not, stop and fix it before going further.

### Ownership matters here

Apply all migration files **as the same role**, and let that role be Supabase's
`postgres` (which is what `supabase db push` and the dashboard SQL editor both
use). The migrations create SECURITY DEFINER helpers that run as their owner,
and `20260823000200_rls.sql` creates policies for `current_user` so those
helpers keep working under `FORCE ROW LEVEL SECURITY` regardless of whether
`postgres` holds `BYPASSRLS` on your project. Applying one file as one role and
the other as a different role would leave the second half pointing at the wrong
owner. To see what you actually have:

```sql
select rolname, rolsuper, rolbypassrls from pg_roles where rolname = current_user;
select polname, polroles::regrole[] from pg_policy
where polname like '%_definer_%';
```

## 4. Frontend configuration

Edit [`js/config.js`](../js/config.js) and fill in `supabaseUrl`,
`supabaseAnonKey` and `googleClientId`. All three are public values.

For Netlify you can instead leave the file alone and inject at deploy time:

```html
<script>window.NCKU_CONFIG = { supabaseUrl: "…", supabaseAnonKey: "…", googleClientId: "…" };</script>
```

## 5. Deploy the verification edge function

```bash
supabase secrets set \
  GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com" \
  NCKU_HOSTED_DOMAIN="gs.ncku.edu.tw" \
  ALLOWED_ORIGINS="http://localhost:5500,https://your-site.netlify.app"

supabase functions deploy verify-ncku-student
```

`SUPABASE_URL`, `SUPABASE_ANON_KEY` and `SUPABASE_SERVICE_ROLE_KEY` are
injected by the platform - do not set them yourself.

This function is the only thing in the system that can set
`ncku_verified = true`. If it is not deployed, Google sign-in will fail
closed and no student will get access.

## 6. Redirect URLs for password reset

Supabase → **Authentication → URL Configuration**:

- Site URL: `https://your-site.netlify.app`
- Redirect URLs (allowlist): `https://your-site.netlify.app/reset-password.html`
  and, for local work, `http://localhost:5500/reset-password.html`

A reset link that points anywhere else is refused by Supabase.

Also turn on **Authentication → Providers → Email → Secure password change**.
With it on, `updateUser({ password })` requires a recent authentication, so a
long-lived stolen session cannot quietly set a new password. It does not get in
the way of recovery: the session minted by a recovery link is recent by
definition.

`reset-password.html` additionally refuses to show its form unless the page was
opened from a recovery link (see [`js/recovery.js`](../js/recovery.js)). A
signed-in administrator who navigates there directly is told to use the emailed
link instead.

## 7. Create the first administrator

There is no admin sign-up page, by design. Every administrator gets their own
account - never a shared Liwen or Student Union password.

1. Supabase → **Authentication → Users → Add user**. Set an email and a
   password, tick "Auto Confirm User". Copy the new user's UUID.
2. SQL editor:

   ```sql
   insert into public.admin_users (user_id, organization, display_name, role, is_active)
   values ('PASTE-UUID-HERE', 'student_union', '你的名字', 'owner', true);
   ```

That account can now sign in at `index.html` with email + password and reach
`admin.html`. From there an **owner** can add further administrators from the
UI (create the Auth user in the dashboard first, then paste its UUID).

To remove someone's access, set `is_active = false`. They keep an Auth
account but lose every row of admin data immediately - RLS re-evaluates on
each request, so no sign-out is required.

### Administrators are organization-scoped

`organization` is not a label; it is the boundary. A `liwen` administrator can
only see and manage Liwen forms, their assignments, their submissions and their
audit entries - and the same in reverse for `student_union`. `owner` and
`editor` are levels **within** one organization: a Liwen owner has no authority
over Student Union data at all. Pick the organization carefully when you insert
the row, because it is immutable afterwards; moving somebody is a deliberate
service-role operation, not a dashboard toggle.

You will want one owner per organization.

### Suspending a student

Suspension is deliberately **not** a table update. `authenticated` holds no
UPDATE privilege on `student_profiles.is_active` at all. It goes through one
audited RPC, restricted to **Student Union owners**:

```sql
select public.set_student_active('STUDENT-UUID', false, 'reason');   -- suspend
select public.set_student_active('STUDENT-UUID', true,  null);       -- restore
```

A Student Union owner can also do this from the admin page. Liwen
administrators cannot suspend students - the least-privileged reading of
"student data is university-side", and the RPC enforces it. A suspended student
loses access to every form and submission immediately, and signing in with
Google again does not lift it.

---

## Running the tests

There are two modes, and they promise different things.

```bash
npm install
npm test                 # local mode: no credentials needed
```

Local mode runs the routing rules, the recovery rule, the Google ID-token
verifier, the edge-function handler, and the **migrations themselves** against
an in-process PostgreSQL (PGlite). It ends by telling you, in as many words,
that live RLS was not executed - because passing here does not mean your
deployed database is safe.

```bash
cp .env.example .env     # fill in the three SUPABASE_* values
npm run test:security
```

Security mode is the one to gate a release on. It fails if the configuration is
missing, if the migrations are not applied to the target project, if any test
is skipped, or if any assertion fails. **Point it at a scratch Supabase
project, not production** - it creates and deletes users.

---

## What must never end up in this repository

- `service_role` key
- Google OAuth **client secret**
- any JWT signing key
- a `.env` file

`.gitignore` covers `.env`, but the real control is habit: the browser only
ever needs the project URL, the publishable anon key, and the Google client
ID.

## Security notes worth keeping in mind

- **Frontend routing is not access control.** `js/guard.js` exists so people
  see a sensible page; `supabase/migrations/20260823000200_rls.sql` is what
  actually stops them. Changes to authorization rules belong in the SQL.
- **`user_metadata` is never consulted.** It is writable by the user. Roles
  come from `admin_users`, eligibility from `student_profiles`, and both are
  written only by trusted paths.
- **An email ending in `@gs.ncku.edu.tw` proves nothing.** The `hd` claim in
  a Google-signed ID token does, and that is what the edge function checks.
- **The ID token is bound to the account being verified.** The Google `sub`
  inside the token must already be linked to that Supabase user, so a borrowed
  NCKU token cannot verify somebody else. There is no nonce check: a nonce the
  same browser just generated proves nothing to the server, and V1 has no
  server-side nonce store to make it real.
- **`ALLOWED_ORIGINS` is required.** With it unset the edge function refuses
  every request rather than answering with `Access-Control-Allow-Origin: *`.
- **Future tables are denied by default.** The RLS migration cancels Supabase's
  default grants to `anon`/`authenticated` for objects created later in
  `public`, so a table added by a future migration is unreachable until someone
  grants and writes policies for it deliberately. If a new table returns
  "permission denied", that is the safety net working, not a bug.
