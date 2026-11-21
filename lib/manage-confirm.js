// The confirm jobs: after a Reticulum config change (POST /api/manage/reticulum), the node keeps the
// change on probation and puts the old config back by itself unless it is confirmed in time. A job
// here is what confirms it, and only once the website can still reach the node over Reticulum.
//
// One job per node; a new change replaces the job of the one before. Every tick (5 seconds) the job
// asks the node's /state as the user who made the change:
//   - the change is no longer pending: done, with how it ended when the node says so;
//   - restarting or rolling back: it waits;
//   - on probation: it probes the node's Reticulum port (the address the status page checks). Once
//     that works and the user still has the manage or admin role, it sends /confirm as that user.
//     200 is done; 409 means the state is read again next tick; a network error, a timeout or 429
//     is tried again. A probe that fails is tried again next tick.
// Before each tick and again right before the confirm, the user must still be the one who made the
// change: the role manage or admin, the same sign-in epoch (no new password, reset or ended
// sessions since), no password to change, a second factor still on, and the session the change was
// made in still there. Otherwise the job gives up (role-gone, signin-changed or session-ended) and
// the node rolls back. A 429 of the node is waited out for as long as it says (at most 5 minutes).
// It sends nothing once the node's time is within 5 seconds of the deadline, and gives up 60 seconds
// after it, or 20 minutes after the start in all. A job that ends writes one manage-confirm line to
// audit.log (one replaced by the next change of its node ends without one: its change was no
// longer pending, or the node would not have taken the next). The jobs live in memory only: when the website restarts, nothing confirms, and the
// node puts the old config back by itself (the safe side).
//
// What the node says is untrusted: it is read through cleanState (manage-api.js), and only the
// fixed sentences here and the node's cleaned message reach the page.
import { probe } from './monitor.js';
import { cleanState } from './manage-api.js';

export const CONFIRM_TICK_MS = 5000;
// No confirm is sent this close to the node's deadline: it might arrive after it.
export const CONFIRM_STOP_BEFORE_SECONDS = 5;
// How long after the deadline the job keeps asking how it ended.
export const CONFIRM_GRACE_SECONDS = 60;
export const CONFIRM_MAX_MS = 20 * 60_000;
// The longest a node's retry_after holds a job back.
export const CONFIRM_MAX_RETRY_MS = 5 * 60_000;
const ROLES = new Set(['manage', 'admin']);
const ID_RE = /^[0-9a-f]{16}$/;
const CODE_RE = /^[a-z_]{1,32}$/;

// The targetOf of the jobs for the nodes of the config (targets: [{host, port}], as the monitor
// probes them): a managed node is known by its address, "host:port", and that is the Reticulum
// listener the probe tries. Gives null for a node that is not one of them.
export function targetsOf(targets) {
  const byKey = new Map(targets.map((t) => [`${t.host}:${t.port}`, { host: t.host, port: t.port }]));
  return (key) => (typeof key === 'string' ? (byKey.get(key.toLowerCase()) ?? null) : null);
}

// How a change that is no longer pending ended, in the page's words.
function endedText(outcome, message) {
  const why = message ? `: ${message}` : '.';
  if (outcome === 'committed') return 'The change passed the test and is kept.';
  if (outcome === 'rolled_back') return `The node put the old config back${why}`;
  if (outcome === 'rollback_failed') return `The node could not put the old config back${why} Check the node in the terminal.`;
  if (outcome === 'left') return `The config was changed on the node meanwhile, so the node left it as it is${why}`;
  return 'The node no longer has this change waiting, and does not say how it ended. Reload the page to see the node.';
}

// client: what createManageClient gives. probeFn(host, port): a TCP probe that resolves {up}.
// targetOf(host): the node's Reticulum {host, port}, or null. store: the user store (lookup(name),
// secondFactorEnabled(name)). epochOf(name): the user's sign-in epoch (login.js), which moves on with
// every change to how they sign in. sessionLive(id): whether a session is still there. audit: the
// audit log (write(event, fields)). now: the website's clock, in ms. setTimer and clearTimer: for
// tests; a timer's callback returns the promise of its tick.
export function createConfirmJobs({ client, probeFn = probe, targetOf, store, epochOf, sessionLive, audit, now = Date.now, tickMs = CONFIRM_TICK_MS, log = console.error, setTimer = setTimeout, clearTimer = clearTimeout }) {
  if (typeof epochOf !== 'function' || typeof sessionLive !== 'function') throw new Error('createConfirmJobs needs epochOf and sessionLive');
  const jobs = new Map();
  const finished = (job) => job.state === 'done' || job.state === 'gave-up';
  // The node's time now, as far as the website knows it: its clock moved on by ours.
  const nodeNow = (job) => now() / 1000 + job.offset;

  function set(job, state, message) {
    job.state = state;
    job.message = message;
    job.updatedAt = now();
  }

  function halt(job) {
    job.stopped = true;
    if (job.timer !== null) clearTimer(job.timer);
    job.timer = null;
  }

  // Ends a job, with its one line in audit.log.
  async function finish(job, state, result, outcome, message) {
    set(job, state, message);
    job.outcome = outcome;
    halt(job);
    await audit.write('manage-confirm', { actor: job.actor, host: job.host, id: job.id, result, ...(outcome ? { outcome } : {}) });
  }

  // Why the job may no longer act for its user, as [result, message], or null when it may.
  function signinProblem(job) {
    const user = store.lookup(job.actor);
    const back = 'The node puts the old config back by itself.';
    if (!user || !ROLES.has(user.role)) return ['role-gone', `${job.actor} no longer has the manage or admin role, so the website did not keep the change. ${back}`];
    if (epochOf(job.actor) !== job.epoch || user.mustChangePassword === true || !store.secondFactorEnabled(job.actor)) return ['signin-changed', `How ${job.actor} signs in changed since the change was made, so the website did not keep it. ${back}`];
    if (!sessionLive(job.sessionId)) return ['session-ended', `The session the change was made in has ended, so the website did not keep it. ${back}`];
    return null;
  }

  // How long a 429 of the node asks the job to wait, in ms, or null for another answer.
  function retryOf(r) {
    if (!r.ok || r.status !== 429) return null;
    const sec = r.body?.retry_after;
    const ms = Number.isSafeInteger(sec) && sec > 0 ? sec * 1000 : tickMs;
    return Math.min(Math.max(ms, tickMs), CONFIRM_MAX_RETRY_MS);
  }

  const tooLate = (job) => job.confirmBy !== null && nodeNow(job) >= job.confirmBy - CONFIRM_STOP_BEFORE_SECONDS;
  const TOO_LATE = 'It is too late to keep the change. Waiting for the node to put the old config back.';

  function giveUp(job) {
    const probeFailed = job.problem === 'probe-failed';
    const message = probeFailed
      ? "The website could not reach this node's Reticulum port in time, so it did not keep the change. The node puts the old config back by itself."
      : 'The website could not keep the change in time. The node puts the old config back by itself.';
    return finish(job, 'gave-up', probeFailed ? 'probe-failed' : 'gave-up', null, message);
  }

  async function tick(job) {
    if (now() - job.started >= CONFIRM_MAX_MS || (job.confirmBy !== null && nodeNow(job) >= job.confirmBy + CONFIRM_GRACE_SECONDS)) return giveUp(job);
    const early = signinProblem(job);
    if (early) return finish(job, 'gave-up', early[0], null, early[1]);
    const r = await client.call(job.host, 'GET', '/manage/v1/state', job.actor);
    if (job.stopped) return;
    if (!r.ok || r.status !== 200) {
      job.problem = 'state';
      job.waitMs = retryOf(r);
      return set(job, job.state, 'The node could not be asked how the change is going. Asking again.');
    }
    const s = cleanState(r.body);
    if (s.node_time !== null) job.offset = s.node_time - now() / 1000;
    const p = s.pending;
    if (p === null || p.id !== job.id) {
      const res = s.reticulum_result?.id === job.id ? s.reticulum_result : null;
      const outcome = res && res.outcome !== 'unknown' ? res.outcome : null;
      return finish(job, 'done', outcome === 'committed' ? 'ok' : 'not_pending', outcome, endedText(outcome, res?.message ?? ''));
    }
    job.nodeState = p.state === 'unknown' ? null : p.state;
    if (p.state === 'restarting') return set(job, 'waiting', 'Reticulum is restarting with the change.');
    if (p.state === 'rolling_back') return set(job, 'waiting', 'The node is putting the old config back.');
    if (p.state !== 'probation') return set(job, 'waiting', 'Waiting for the node to test the change.');
    if (p.confirm_by !== null) job.confirmBy = p.confirm_by;
    if (tooLate(job)) return set(job, 'waiting', TOO_LATE);

    set(job, 'probing', 'Checking that the website can still reach the node over Reticulum.');
    const target = targetOf(job.host);
    const up = target ? (await probeFn(target.host, target.port))?.up === true : false;
    if (job.stopped) return;
    if (!up) {
      job.problem = 'probe-failed';
      return set(job, 'probing', "The website cannot reach the node's Reticulum port yet. Trying again.");
    }
    // Asked again: the probe may have taken a while.
    const late = signinProblem(job);
    if (late) return finish(job, 'gave-up', late[0], null, late[1]);
    if (tooLate(job)) return set(job, 'waiting', TOO_LATE);
    set(job, 'confirming', 'Keeping the change.');
    const c = await client.call(job.host, 'POST', '/manage/v1/confirm', job.actor, { id: job.id });
    if (job.stopped) return;
    if (c.ok && c.status === 200) return finish(job, 'done', 'ok', 'committed', endedText('committed'));
    const code = c.ok && typeof c.body?.error === 'string' && CODE_RE.test(c.body.error) ? c.body.error : c.ok ? `http_${c.status}` : c.error;
    // Refused for good: the node will not take a confirm of this change from this user.
    if (c.ok && (c.status === 400 || c.status === 403 || c.status === 404)) {
      return finish(job, 'gave-up', code, null, 'The node did not let the website keep the change. It puts the old config back by itself.');
    }
    // 409: the change moved on (the state is read again next tick); anything else is tried again,
    // a 429 once the node's wait is over.
    job.problem = code;
    job.waitMs = retryOf(c);
    return set(job, 'waiting', 'The node did not take the confirm yet. Trying again.');
  }

  function schedule(job) {
    if (job.stopped || finished(job)) return;
    const wait = job.waitMs ?? tickMs;
    job.waitMs = null;
    job.timer = setTimer(() => {
      job.timer = null;
      return tick(job)
        .catch((err) => log(`manage: the confirm job for ${job.host} failed unexpectedly: ${err?.message ?? err}`))
        .then(() => schedule(job));
    }, wait);
    job.timer?.unref?.();
  }

  // Starts the job for a change the node took (host, its id, the user who made it, the session it was
  // made in), in place of the node's job before. Gives its status, or null when the arguments are not
  // a change.
  function start({ host, id, actor, sessionId, confirmSeconds = null } = {}) {
    if (typeof host !== 'string' || typeof id !== 'string' || !ID_RE.test(id) || typeof actor !== 'string' || actor === '' || typeof sessionId !== 'string') return null;
    const key = host.toLowerCase();
    const old = jobs.get(key);
    if (old) halt(old);
    const t = now();
    const job = { host: key, id, actor, sessionId, epoch: epochOf(actor), confirmSeconds, started: t, state: 'waiting', nodeState: 'restarting', outcome: null, message: 'Reticulum is restarting with the change.', confirmBy: null, updatedAt: t, offset: 0, problem: null, waitMs: null, timer: null, stopped: false };
    jobs.set(key, job);
    schedule(job);
    return status(key);
  }

  // The job of a node: null, or {id, state: waiting|probing|confirming|done|gave-up, nodeState (what
  // the node last said of the change: restarting|probation|rolling_back, or null), outcome, message,
  // confirmBy (the node's deadline, in its unix seconds), updatedAt}.
  function status(host) {
    const job = typeof host === 'string' ? jobs.get(host.toLowerCase()) : undefined;
    if (!job) return null;
    return { id: job.id, state: job.state, nodeState: finished(job) ? null : job.nodeState, outcome: job.outcome, message: job.message, confirmBy: job.confirmBy, updatedAt: new Date(job.updatedAt).toISOString() };
  }

  function stopAll() {
    for (const job of jobs.values()) halt(job);
  }

  return { start, status, stopAll };
}
