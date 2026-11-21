// The confirm jobs (lib/manage-confirm.js) on a fake clock, with fake timers, a fake probe and a
// fake client: when a Reticulum change is kept, when it is not, and what audit.log gets.
import test from 'node:test';
import assert from 'node:assert/strict';
import { CONFIRM_MAX_MS, createConfirmJobs } from '../lib/manage-confirm.js';

const HOST = 'a.test:1';
const ID = '00112233aabbccdd';
const T0 = 1_800_000_000_000;

// pending: what the node says is pending, by its state, with a deadline confirmSeconds after now.
function pendingOf(state, clock, extra = {}) {
  const at = Math.floor(clock.t / 1000);
  return { id: ID, actor: 'bob', state, applied_at: at, confirm_seconds: 300, healthy_at: state === 'probation' ? at : null, confirm_by: state === 'probation' ? at + 300 : null, changes: [{ path: ['interfaces', 'Hilltop TCP'], key: 'enabled', from: 'yes', to: 'no' }], problems: [], ...extra };
}

// The jobs, with: node, what the fake node says (node.pending, node.result, node.skew, and
// node.confirm(): the answer to /confirm); up(): what the probe gives; roles by user.
// signin: what the store and login say of a user ({epoch, mustChangePassword, secondFactor}) and
// which sessions are live.
function harness({ up = () => true, roles = { bob: 'manage' } } = {}) {
  const signin = { epoch: 7, mustChangePassword: false, secondFactor: true, live: new Set(['sess-1']) };
  const clock = { t: T0 };
  const timers = new Map();
  let next = 0;
  const calls = [];
  const probes = [];
  const lines = [];
  const logs = [];
  const node = { pending: null, result: null, skew: 0, confirm: () => ({ ok: true, status: 200, body: { id: ID, state: 'committed' } }), state: null };
  const client = {
    call: async (...args) => {
      calls.push(args);
      const [, method, target] = args;
      if (method === 'GET' && target === '/manage/v1/state') {
        if (node.state) return node.state();
        return { ok: true, status: 200, body: { v: 1, node_time: Math.floor(clock.t / 1000) + node.skew, pending: node.pending, reticulum_result: node.result } };
      }
      if (method === 'POST' && target === '/manage/v1/confirm') return node.confirm();
      throw new Error(`unexpected ${method} ${target}`);
    },
  };
  const jobs = createConfirmJobs({
    client,
    probeFn: async (host, port) => (probes.push([host, port]), { up: up() }),
    targetOf: (key) => (key === HOST ? { host: 'a.test', port: 1 } : null),
    store: { lookup: (name) => (Object.hasOwn(roles, name) ? { name, role: roles[name], mustChangePassword: signin.mustChangePassword } : null), secondFactorEnabled: () => signin.secondFactor },
    epochOf: () => signin.epoch,
    sessionLive: (id) => signin.live.has(id),
    audit: { write: async (event, fields) => lines.push({ event, ...fields }) },
    now: () => clock.t,
    log: (m) => logs.push(m),
    setTimer: (f, ms) => (timers.set(++next, { f, ms }), next),
    clearTimer: (id) => timers.delete(id),
  });
  // Runs the next timer, with the clock moved on by its wait.
  const tick = async () => {
    const [id, t] = timers.entries().next().value;
    timers.delete(id);
    clock.t += t.ms;
    await t.f();
  };
  const confirms = () => calls.filter((c) => c[2] === '/manage/v1/confirm');
  return { clock, timers, calls, probes, lines, logs, node, jobs, tick, confirms, roles, signin };
}

test('a change that comes up healthy and can be reached is confirmed as the user who made it', async () => {
  const h = harness();
  h.node.pending = pendingOf('restarting', h.clock);
  const first = h.jobs.start({ host: 'A.TEST:1', id: ID, actor: 'bob', sessionId: 'sess-1', confirmSeconds: 300 });
  assert.equal(first.state, 'waiting');
  assert.equal(first.id, ID);
  assert.equal(h.timers.size, 1);
  assert.equal([...h.timers.values()][0].ms, 5000);
  await h.tick();
  assert.equal(h.jobs.status(HOST).state, 'waiting', 'restarting: nothing is probed yet');
  assert.equal(h.probes.length, 0);
  assert.deepEqual(h.calls[0], [HOST, 'GET', '/manage/v1/state', 'bob']);
  h.node.pending = pendingOf('probation', h.clock);
  const deadline = h.node.pending.confirm_by;
  await h.tick();
  assert.deepEqual(h.probes, [['a.test', 1]], "the node's address from the config is probed");
  assert.deepEqual(h.confirms(), [[HOST, 'POST', '/manage/v1/confirm', 'bob', { id: ID }]]);
  const done = h.jobs.status(HOST);
  assert.deepEqual({ ...done, updatedAt: undefined }, { id: ID, state: 'done', nodeState: null, checks: [], outcome: 'committed', message: 'The change passed the test and is kept.', confirmBy: deadline, updatedAt: undefined });
  assert.equal(typeof done.updatedAt, 'string');
  assert.equal(h.timers.size, 0, 'a finished job asks nothing more');
  assert.deepEqual(h.lines, [{ event: 'manage-confirm', actor: 'bob', host: HOST, id: ID, result: 'ok', outcome: 'committed' }]);
  assert.equal(h.jobs.status('b.test:2'), null);
  assert.equal(h.jobs.status(5), null);
});

test('a probe that fails sends no confirm, is tried every tick, stops near the deadline and gives up after it', async () => {
  const h = harness({ up: () => false });
  h.node.pending = pendingOf('probation', h.clock);
  const deadline = h.node.pending.confirm_by;
  h.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
  let ticks = 0;
  while (h.timers.size && ticks < 200) {
    await h.tick();
    ticks++;
  }
  assert.equal(h.confirms().length, 0, 'never confirmed');
  // Probed every tick (every 5 seconds) while the node's time is before the deadline less 5
  // seconds: at 5, 10, ... 290 seconds. Then only asked, until 60 seconds after the deadline.
  assert.equal(deadline, T0 / 1000 + 300);
  assert.equal(h.probes.length, 58);
  assert.equal(h.clock.t, T0 + 360_000, 'it gave up 60 seconds after the deadline');
  const s = h.jobs.status(HOST);
  assert.equal(s.state, 'gave-up');
  assert.equal(s.outcome, null);
  assert.match(s.message, /could not reach this node's Reticulum port in time.*puts the old config back by itself/);
  assert.deepEqual(h.lines, [{ event: 'manage-confirm', actor: 'bob', host: HOST, id: ID, result: 'probe-failed' }]);
});

test('a probe that fails at first and then works confirms on the next tick', async () => {
  let n = 0;
  const h = harness({ up: () => ++n > 2 });
  h.node.pending = pendingOf('probation', h.clock);
  h.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
  await h.tick();
  assert.equal(h.jobs.status(HOST).state, 'probing');
  assert.match(h.jobs.status(HOST).message, /cannot reach the node's Reticulum port yet/);
  await h.tick();
  assert.equal(h.confirms().length, 0);
  await h.tick();
  assert.equal(h.confirms().length, 1);
  assert.equal(h.jobs.status(HOST).outcome, 'committed');
});

test('a confirm that times out, when the node then says the change is kept, is done and ok', async () => {
  const h = harness();
  h.node.pending = pendingOf('probation', h.clock);
  h.node.confirm = () => {
    // The node took it, but the answer was lost.
    h.node.result = { id: ID, outcome: 'committed', at: 1, message: '' };
    h.node.pending = null;
    return { ok: false, error: 'timeout' };
  };
  h.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
  await h.tick();
  assert.equal(h.jobs.status(HOST).state, 'waiting', 'a timeout is tried again');
  assert.equal(h.timers.size, 1);
  await h.tick();
  assert.equal(h.confirms().length, 1, 'no second confirm: the state said it is kept');
  assert.equal(h.jobs.status(HOST).state, 'done');
  assert.equal(h.jobs.status(HOST).outcome, 'committed');
  assert.deepEqual(h.lines.map((l) => l.result), ['ok']);
});

test('a user who lost the role gets no confirm: the job gives up and the node rolls back by itself', async () => {
  const h = harness();
  h.node.pending = pendingOf('probation', h.clock);
  h.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
  h.roles.bob = 'viewer';
  await h.tick();
  assert.equal(h.confirms().length, 0);
  const s = h.jobs.status(HOST);
  assert.equal(s.state, 'gave-up');
  assert.match(s.message, /^bob no longer has the manage or admin role/);
  assert.deepEqual(h.lines.map((l) => l.result), ['role-gone']);
  // A user who is gone altogether: the same.
  const g = harness({ roles: {} });
  g.node.pending = pendingOf('probation', g.clock);
  g.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
  await g.tick();
  assert.equal(g.confirms().length, 0);
  assert.deepEqual(g.lines.map((l) => l.result), ['role-gone']);
});

test('a change the node rolled back, or no longer has, ends the job with what the node says, cleaned', async () => {
  const outcomes = [
    ['rolled_back', 'Reticulum isn’t back as it was: Hilltop TCP‮\u0000', /^The node put the old config back: Reticulum isn’t back as it was: Hilltop TCP$/],
    ['rollback_failed', 'no backup found', /^The node could not put the old config back: no backup found Check the node in the terminal\.$/],
    ['left', '', /^The config was changed on the node meanwhile, so the node left it as it is\.$/],
    ['exploded', 'x', /does not say how it ended/],
  ];
  for (const [outcome, message, words] of outcomes) {
    const h = harness();
    h.node.result = { id: ID, outcome, at: 5, message };
    h.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
    await h.tick();
    const s = h.jobs.status(HOST);
    assert.equal(s.state, 'done', outcome);
    assert.equal(s.outcome, outcome === 'exploded' ? null : outcome, outcome);
    assert.match(s.message, words, outcome);
    assert.deepEqual(h.lines, [{ event: 'manage-confirm', actor: 'bob', host: HOST, id: ID, result: 'not_pending', ...(outcome === 'exploded' ? {} : { outcome }) }]);
  }
  // Another change pending, or a result for another change: this one is over, and how is not known.
  const other = harness();
  other.node.pending = { ...pendingOf('probation', other.clock), id: 'ffffffffffffffff' };
  other.node.result = { id: 'eeeeeeeeeeeeeeee', outcome: 'committed', at: 1, message: '' };
  other.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
  await other.tick();
  assert.equal(other.jobs.status(HOST).state, 'done');
  assert.equal(other.jobs.status(HOST).outcome, null);
  assert.equal(other.confirms().length, 0);
});

test('while the node rolls back, or says a state it does not know, the job waits and sends nothing', async () => {
  const h = harness();
  h.node.pending = pendingOf('rolling_back', h.clock);
  h.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
  await h.tick();
  assert.equal(h.jobs.status(HOST).state, 'waiting');
  assert.equal(h.jobs.status(HOST).message, 'The node is putting the old config back.');
  h.node.pending = { ...pendingOf('probation', h.clock), state: '<script>' };
  await h.tick();
  assert.equal(h.jobs.status(HOST).state, 'waiting');
  assert.equal(h.probes.length + h.confirms().length, 0);
  h.node.result = { id: ID, outcome: 'rolled_back', at: 1, message: 'no confirm by the deadline' };
  h.node.pending = null;
  await h.tick();
  assert.equal(h.jobs.status(HOST).outcome, 'rolled_back');
});

test('409 reads the state again; 403 gives up with the code; 429 and network errors are tried again', async () => {
  const h = harness();
  h.node.pending = pendingOf('probation', h.clock);
  const answers = [{ ok: true, status: 409, body: { error: 'not_pending', state: 'restarting' } }, { ok: true, status: 429, body: { error: 'rate_limited', retry_after: 3 } }, { ok: false, error: 'network' }, { ok: false, error: 'unsigned' }, { ok: true, status: 403, body: { error: 'not_allowed' } }];
  h.node.confirm = () => answers.shift();
  h.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
  for (let i = 0; i < 4; i++) {
    await h.tick();
    assert.equal(h.jobs.status(HOST).state, 'waiting', `try ${i + 1}`);
  }
  await h.tick();
  assert.equal(h.confirms().length, 5);
  assert.equal(h.jobs.status(HOST).state, 'gave-up');
  assert.match(h.jobs.status(HOST).message, /did not let the website keep the change/);
  assert.deepEqual(h.lines.map((l) => l.result), ['not_allowed']);
  // A refusal without a code the website knows is named by its status.
  const odd = harness();
  odd.node.pending = pendingOf('probation', odd.clock);
  odd.node.confirm = () => ({ ok: true, status: 400, body: { error: 'Bad <b>' } });
  odd.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
  await odd.tick();
  assert.deepEqual(odd.lines.map((l) => l.result), ['http_400']);
});

test('a node that cannot be asked is asked again, and the job gives up after 20 minutes in all', async () => {
  const h = harness();
  h.node.state = () => ({ ok: false, error: 'network' });
  h.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
  await h.tick();
  assert.match(h.jobs.status(HOST).message, /could not be asked how the change is going/);
  let ticks = 1;
  while (h.timers.size && ticks < 1000) {
    await h.tick();
    ticks++;
  }
  assert.equal(ticks, CONFIRM_MAX_MS / 5000);
  assert.equal(h.jobs.status(HOST).state, 'gave-up');
  assert.deepEqual(h.lines.map((l) => l.result), ['gave-up']);
  assert.equal(h.confirms().length, 0);
});

test("the deadline is the node's: a node clock that is ahead stops the confirms sooner", async () => {
  const h = harness();
  h.node.skew = 290;
  // The node says the deadline is 300 seconds after its own now, which is 290 seconds ahead of ours.
  h.node.pending = { ...pendingOf('probation', h.clock), confirm_by: Math.floor(T0 / 1000) + 290 + 300 };
  h.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
  h.node.confirm = () => ({ ok: false, error: 'timeout' });
  await h.tick();
  assert.equal(h.confirms().length, 1, 'well before the deadline');
  // Close to the node's deadline: no more confirms, whatever our own clock says.
  h.clock.t += 290_000;
  await h.tick();
  assert.equal(h.confirms().length, 1);
  assert.match(h.jobs.status(HOST).message, /too late to keep the change/);
});

test('a new change replaces the job of the one before; stopAll ends every job; a bad start is refused', async () => {
  const h = harness();
  h.node.pending = pendingOf('restarting', h.clock);
  h.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
  assert.equal(h.timers.size, 1);
  const again = h.jobs.start({ host: HOST, id: 'ffffffffffffffff', actor: 'bob', sessionId: 'sess-1' });
  assert.equal(again.id, 'ffffffffffffffff');
  assert.equal(h.timers.size, 1, "the old job's timer is cleared");
  h.jobs.start({ host: 'b.test:2', id: ID, actor: 'bob', sessionId: 'sess-1' });
  assert.equal(h.timers.size, 2);
  h.jobs.stopAll();
  assert.equal(h.timers.size, 0);
  for (const bad of [undefined, {}, { host: HOST, id: 'xyz', actor: 'bob' }, { host: HOST, id: ID, actor: '' }, { host: 5, id: ID, actor: 'bob' }]) assert.equal(h.jobs.start(bad), null, JSON.stringify(bad));
});

test('a job whose node has no address is never confirmed; a client that throws is logged and tried again', async () => {
  const h = harness();
  h.node.pending = pendingOf('probation', h.clock);
  h.jobs.start({ host: 'c.test:3', id: ID, actor: 'bob', sessionId: 'sess-1' });
  await h.tick();
  assert.equal(h.probes.length, 0);
  assert.equal(h.confirms().length, 0);
  assert.equal(h.jobs.status('c.test:3').state, 'probing');
  let threw = 0;
  h.node.state = () => {
    threw++;
    throw new Error('boom');
  };
  await h.tick();
  assert.equal(threw, 1);
  assert.match(h.logs[0], /^manage: the confirm job for c\.test:3 failed unexpectedly: boom$/);
  assert.equal(h.timers.size, 1, 'it carries on');
});

test("targetsOf finds a managed node's Reticulum address by its key, the host:port the status page probes", async () => {
  const { targetsOf } = await import('../lib/manage-confirm.js');
  const of = targetsOf([{ host: 'a.test', port: 1 }, { host: 'rns.example.org', port: 4242 }]);
  assert.deepEqual(of('a.test:1'), { host: 'a.test', port: 1 });
  assert.deepEqual(of('RNS.example.org:4242'), { host: 'rns.example.org', port: 4242 });
  for (const k of ['a.test:2', 'a.test', '', null, 5]) assert.equal(of(k), null, String(k));
});

test('a change in how the user signs in, a password to change, no second factor or an ended session: no confirm, and the job gives up', async () => {
  const cases = [
    ['epoch', (h) => h.signin.epoch++, 'signin-changed', /^How bob signs in changed since the change was made/],
    ['must change password', (h) => (h.signin.mustChangePassword = true), 'signin-changed', /^How bob signs in changed/],
    ['second factor off', (h) => (h.signin.secondFactor = false), 'signin-changed', /^How bob signs in changed/],
    ['session ended', (h) => h.signin.live.clear(), 'session-ended', /^The session the change was made in has ended/],
  ];
  for (const [what, change, result, words] of cases) {
    // Before the tick.
    const h = harness();
    h.node.pending = pendingOf('probation', h.clock);
    h.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
    change(h);
    await h.tick();
    assert.equal(h.confirms().length, 0, what);
    assert.equal(h.calls.length, 0, `${what}: the node is not even asked`);
    assert.equal(h.jobs.status(HOST).state, 'gave-up', what);
    assert.match(h.jobs.status(HOST).message, words, what);
    assert.match(h.jobs.status(HOST).message, /The node puts the old config back by itself\.$/, what);
    assert.deepEqual(h.lines, [{ event: 'manage-confirm', actor: 'bob', host: HOST, id: ID, result }], what);
    // While the probe runs: asked again right before the confirm.
    const g = harness({ up: () => (change(g), true) });
    g.node.pending = pendingOf('probation', g.clock);
    g.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
    await g.tick();
    assert.equal(g.probes.length, 1, what);
    assert.equal(g.confirms().length, 0, `${what} during the probe`);
    assert.deepEqual(g.lines.map((l) => l.result), [result], what);
  }
  // The epoch is the one at the start: a later start with the new epoch confirms.
  const h = harness();
  h.signin.epoch = 9;
  h.node.pending = pendingOf('probation', h.clock);
  h.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
  await h.tick();
  assert.equal(h.confirms().length, 1);
  // A start without the session is refused; so are jobs made without the sign-in checks.
  assert.equal(h.jobs.start({ host: HOST, id: ID, actor: 'bob' }), null);
  assert.throws(() => createConfirmJobs({ client: {}, targetOf: () => null, store: {}, audit: {} }), /needs epochOf and sessionLive/);
});

test("a 429 of the node is waited out for its retry_after, at least a tick and at most 5 minutes", async () => {
  const h = harness();
  // A deadline far enough away for the waits.
  h.node.pending = pendingOf('probation', h.clock, { confirm_seconds: 900, confirm_by: Math.floor(T0 / 1000) + 900 });
  const states = [{ ok: true, status: 429, body: { error: 'rate_limited', retry_after: 40 } }, { ok: true, status: 429, body: { error: 'rate_limited' } }];
  h.node.state = () => states.shift() ?? { ok: true, status: 200, body: { v: 1, node_time: Math.floor(h.clock.t / 1000), pending: h.node.pending, reticulum_result: null } };
  const confirms = [{ ok: true, status: 429, body: { error: 'rate_limited', retry_after: 99_999 } }, { ok: true, status: 429, body: { error: 'rate_limited', retry_after: 1 } }];
  h.node.confirm = () => confirms.shift() ?? { ok: true, status: 200, body: {} };
  h.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
  const waits = [];
  for (let i = 0; i < 5 && h.timers.size; i++) {
    waits.push([...h.timers.values()][0].ms);
    await h.tick();
  }
  assert.deepEqual(waits, [5000, 40_000, 5000, 300_000, 5000]);
  assert.equal(h.confirms().length, 3);
  assert.equal(h.jobs.status(HOST).outcome, 'committed');
});

test('the deadline is checked again after the probe: a probe that ran into it sends no confirm', async () => {
  const h = harness({ up: () => ((h.clock.t += 296_000), true) });
  h.node.pending = pendingOf('probation', h.clock);
  h.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
  await h.tick();
  assert.equal(h.probes.length, 1);
  assert.equal(h.confirms().length, 0);
  assert.match(h.jobs.status(HOST).message, /too late to keep the change/);
  assert.equal(h.jobs.status(HOST).nodeState, 'probation');
});

test('a job replaced while its tick is in flight sends nothing more and audits nothing', async () => {
  // In flight in the state read.
  let release;
  const h = harness({ up: () => true });
  const slow = new Promise((r) => (release = r));
  h.node.pending = pendingOf('probation', h.clock);
  // Holds the state answer of the first tick until the job is replaced.
  let first = true;
  h.node.state = () => {
    const answer = { ok: true, status: 200, body: { v: 1, node_time: Math.floor(h.clock.t / 1000), pending: h.node.pending, reticulum_result: null } };
    if (!first) return answer;
    first = false;
    return slow.then(() => answer);
  };
  h.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
  const [id, t] = h.timers.entries().next().value;
  h.timers.delete(id);
  const running = t.f();
  await new Promise((r) => setImmediate(r));
  const other = 'ffffffffffffffff';
  h.jobs.start({ host: HOST, id: other, actor: 'bob', sessionId: 'sess-1' });
  release();
  await running;
  assert.equal(h.probes.length, 0, 'the old job did not go on to probe');
  assert.equal(h.confirms().length, 0);
  assert.deepEqual(h.lines, []);
  assert.equal(h.jobs.status(HOST).id, other);
  assert.equal(h.timers.size, 1, "only the new job's timer");

  // In flight in the confirm itself: its answer is dropped, nothing is audited.
  const g = harness();
  g.node.pending = pendingOf('probation', g.clock);
  let answer;
  g.node.confirm = () => new Promise((r) => (answer = r));
  g.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
  const [gid, gt] = g.timers.entries().next().value;
  g.timers.delete(gid);
  const going = gt.f();
  for (let i = 0; i < 20 && !answer; i++) await new Promise((r) => setImmediate(r));
  assert.ok(answer, 'the confirm was sent');
  g.jobs.start({ host: HOST, id: other, actor: 'bob', sessionId: 'sess-1' });
  answer({ ok: true, status: 200, body: {} });
  await going;
  assert.deepEqual(g.lines, []);
  assert.equal(g.jobs.status(HOST).id, other);
  assert.equal(g.jobs.status(HOST).state, 'waiting');
});

test("the job passes on the node's own checks of the change, cleaned, while it runs", async () => {
  const h = harness({ up: () => false });
  h.node.pending = pendingOf('probation', h.clock, { checks: [{ interface: 'Hilltop TCP', kind: 'self_test', result: 'passed' }, { interface: 'Radio ', kind: 'online', result: 'no_traffic' }, { interface: 'X', kind: 'self_test', result: 'traffic' }] });
  h.jobs.start({ host: HOST, id: ID, actor: 'bob', sessionId: 'sess-1' });
  assert.deepEqual(h.jobs.status(HOST).checks, []);
  await h.tick();
  assert.deepEqual(h.jobs.status(HOST).checks, [{ interface: 'Hilltop TCP', kind: 'self_test', result: 'passed' }, { interface: 'Radio', kind: 'online', result: 'no_traffic' }]);
  // A copy: changing what status gave changes nothing in the job.
  h.jobs.status(HOST).checks[0].result = 'failed';
  assert.equal(h.jobs.status(HOST).checks[0].result, 'passed');
});
