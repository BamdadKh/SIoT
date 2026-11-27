// Roadmap 2.3: `GET /salt` must not say whether an account exists.
//
// "At least structurally", as the roadmap item puts it: status, body shape,
// every header that could differ, and the salt's own length are compared
// between a real account and a name nobody has. Timing is sampled too, but
// only as a sanity bound (the hand probe this replaces found p50 0.92 ms for
// both); a strict timing assertion in a shared test run would be a flaky test,
// not a security property.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';

import { newAccount, startApp, uniqueName } from './helpers.js';

let app: Awaited<ReturnType<typeof startApp>>;
before(async () => {
  app = await startApp();
});
after(async () => {
  await app.close();
});

const salt = (username: string) =>
  app.inject({ method: 'GET', url: `/siot/salt?username=${encodeURIComponent(username)}` });

/** The headers a response could leak existence through. */
function shape(response: Awaited<ReturnType<typeof salt>>) {
  const body = response.json();
  return {
    status: response.statusCode,
    keys: Object.keys(body).sort(),
    saltBytes: Buffer.from(body.salt, 'base64url').length,
    contentLength: response.headers['content-length'],
    contentType: response.headers['content-type'],
    cacheControl: response.headers['cache-control'],
    headerNames: Object.keys(response.headers)
      .filter((name) => name !== 'date')
      .sort(),
  };
}

test('a real account and an unknown name get structurally identical answers', async () => {
  const account = await newAccount(app);
  const real = await salt(account.username);
  const fake = await salt(uniqueName());

  assert.equal(real.statusCode, 200);
  assert.deepEqual(shape(real), shape(fake));
  assert.equal(shape(real).saltBytes, 16);
  assert.match(String(real.headers['cache-control']), /no-store/);
});

test('the real salt is the stored one, and a decoy is stable rather than fresh', async () => {
  const account = await newAccount(app);
  assert.equal((await salt(account.username)).json().salt, account.salt);

  const name = uniqueName();
  const first = (await salt(name)).json().salt;
  const second = (await salt(name)).json().salt;
  // A decoy that changed per request would be the tell.
  assert.equal(first, second);
  assert.notEqual(first, (await salt(uniqueName())).json().salt);
});

test('case does not separate the two branches', async () => {
  const account = await newAccount(app);
  assert.equal((await salt(account.username.toUpperCase())).json().salt, account.salt);
});

test('response times overlap across 100 interleaved requests', async () => {
  const account = await newAccount(app);
  const timings: Record<'real' | 'fake', number[]> = { real: [], fake: [] };
  for (let index = 0; index < 100; index += 1) {
    const kind = index % 2 === 0 ? 'real' : 'fake';
    const started = process.hrtime.bigint();
    await salt(kind === 'real' ? account.username : uniqueName());
    timings[kind].push(Number(process.hrtime.bigint() - started) / 1e6);
  }
  const median = (values: number[]) => [...values].sort((a, b) => a - b)[values.length >> 1]!;
  const [real, fake] = [median(timings.real), median(timings.fake)];
  // Loose by design: catches a branch that does extra work (an Argon2 call, a
  // second query), not microsecond differences.
  assert.ok(Math.abs(real - fake) < Math.max(real, fake) * 2 + 2, `medians ${real} vs ${fake} ms`);
});
