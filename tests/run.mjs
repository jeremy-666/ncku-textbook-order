// Test runner with two deliberately different contracts.
//
//   local     - everything that needs no credentials. Passing here says the
//               logic and the SQL are sound; it does NOT say the deployed
//               database is safe, and it prints exactly that.
//   security  - the mode you gate a release on. Live Supabase RLS must run:
//               absent configuration, unapplied migrations, a skipped suite or
//               a failed assertion all fail the run.
//
//   node tests/run.mjs local
//   node tests/run.mjs security

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const ENV_FILE = fileURLToPath(new URL('../.env', import.meta.url));

const OFFLINE_SUITES = [
  'tests/routing.test.mjs',
  'tests/recovery.test.mjs',
  'tests/google-id-token.test.mjs',
  'tests/edge-function.test.mjs',
  'tests/sql-policies.test.mjs',
];
const LIVE_SUITES = ['tests/rls.test.mjs'];

const mode = process.argv[2] ?? 'local';
if (!['local', 'security'].includes(mode)) {
  console.error(`unknown mode "${mode}" - expected local or security`);
  process.exit(2);
}

const security = mode === 'security';
const suites = security ? [...OFFLINE_SUITES, ...LIVE_SUITES] : OFFLINE_SUITES;

const args = ['--test'];
if (existsSync(ENV_FILE)) args.unshift(`--env-file=${ENV_FILE}`);
else if (security) {
  fail(
    'security mode needs .env with SUPABASE_URL, SUPABASE_ANON_KEY and ' +
      'SUPABASE_SERVICE_ROLE_KEY for a scratch project (see .env.example).'
  );
}
args.push(...suites);

const child = spawn(process.execPath, args, {
  cwd: ROOT,
  env: { ...process.env, ...(security ? { NCKU_REQUIRE_DB: '1' } : {}) },
  stdio: ['inherit', 'pipe', 'inherit'],
});

let output = '';
child.stdout.on('data', (chunk) => {
  output += chunk;
  process.stdout.write(chunk);
});

child.on('close', (code) => {
  const skipped = Number(/^ℹ skipped (\d+)$/m.exec(output)?.[1] ?? 0);
  const passed = Number(/^ℹ pass (\d+)$/m.exec(output)?.[1] ?? 0);

  if (code !== 0) process.exit(code ?? 1);

  if (!security) {
    console.log(
      [
        '',
        '─'.repeat(72),
        `local mode: ${passed} tests passed WITHOUT a live database.`,
        'Live Supabase RLS was NOT executed, so this run does not verify the',
        'deployed authorization boundary. Run `npm run test:security` against a',
        'scratch project before trusting it.',
        '─'.repeat(72),
      ].join('\n')
    );
    process.exit(0);
  }

  if (skipped > 0) {
    fail(`security mode: ${skipped} test(s) were skipped. Live RLS verification must not be skipped.`);
  }
  if (passed === 0) {
    fail('security mode: no tests reported as passing.');
  }

  console.log(
    ['', '─'.repeat(72), `security mode: ${passed} tests passed, 0 skipped, live RLS included.`, '─'.repeat(72)].join('\n')
  );
});

function fail(message) {
  console.error(`\n${'─'.repeat(72)}\nFAILED: ${message}\n${'─'.repeat(72)}`);
  process.exit(1);
}
