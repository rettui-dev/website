// Alerts: a message to the operator when a node goes down or comes back. They are
// sent only by the monitor, to the channels in the config file, and never because
// of anything a visitor sends. Sending never blocks or fails a check: alerts wait
// in a small queue, are tried a few times with a growing wait, and a failure is
// logged without the address or the secrets of the channel.
import crypto from 'node:crypto';
import { sendMail } from './smtp.js';

export const WEBHOOK_TIMEOUT_MS = 10_000;
export const MAX_QUEUE = 100;
export const MAX_ATTEMPTS = 3;
// The wait before the second and the third try.
export const RETRY_DELAYS_MS = [5000, 30_000];
export const MAX_SENDING = 2;
// What is sent when alerts.events is not set; announce_queue has to be asked for.
export const EVENTS = ['down', 'recovered'];
export const ALL_EVENTS = [...EVENTS, 'announce_queue'];
export const DEFAULT_QUEUE_SAMPLES = 3;
export const FORMATS = ['generic', 'ntfy', 'discord', 'slack'];

const pad = (n) => String(n).padStart(2, '0');

// "12:03 UTC", with the date when it is not the day of `now`.
export function utcTime(time, now) {
  const d = new Date(time);
  const iso = d.toISOString();
  const clock = `${iso.slice(11, 16)} UTC`;
  return iso.slice(0, 10) === new Date(now).toISOString().slice(0, 10) ? clock : `${iso.slice(0, 10)} ${clock}`;
}

// "3m 20s", "2h 5m": the two biggest units.
export function spanText(ms) {
  const s = Math.max(0, Math.round(ms / 1000));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${pad(m)}m`;
  if (m > 0) return `${m}m ${pad(s % 60)}s`;
  return `${s}s`;
}

// The plain words of one alert. event: {type, key, name, start, end, at, repeat}.
export function alertText(event, now = event.at) {
  const who = event.name ? `${event.name} (${event.key})` : event.key;
  if (event.type === 'queue_full') {
    const waiting = Number.isInteger(event.queued) ? ` (${event.queued} waiting)` : '';
    return `${who} has a full announce queue${waiting}: an interface is at its limit and drops new announces.`;
  }
  if (event.type === 'queue_cleared') return `${who} announce queue is no longer full (it was full for ${spanText(event.end - event.start)}).`;
  const since = utcTime(event.start, now);
  if (event.type === 'recovered') return `${who} is back up after ${spanText(event.end - event.start)} (down since ${since}).`;
  if (event.repeat) return `${who} is still down since ${since} (${spanText(event.at - event.start)}).`;
  return `${who} is down since ${since}.`;
}

export function alertSubject(event) {
  const who = event.name ?? event.key;
  if (event.type === 'queue_full') return `[rettui] ${who} announce queue is full`;
  if (event.type === 'queue_cleared') return `[rettui] ${who} announce queue is clear`;
  if (event.type === 'recovered') return `[rettui] ${who} is back up`;
  return `[rettui] ${who} is down`;
}

// The body of a webhook, by format.
export function webhookBody(format, event, text) {
  const iso = (t) => (t === null || t === undefined ? null : new Date(t).toISOString());
  if (format === 'discord') return JSON.stringify({ content: text });
  if (format === 'slack') return JSON.stringify({ text });
  if (format === 'ntfy') return text;
  return JSON.stringify({
    event: event.repeat ? 'still_down' : event.type === 'queue_full' ? 'announce_queue_full' : event.type === 'queue_cleared' ? 'announce_queue_cleared' : event.type,
    host: event.key,
    name: event.name ?? null,
    message: text,
    since: iso(event.start),
    recoveredAt: iso(event.end),
    sentAt: iso(event.at),
    durationSeconds: Math.round(((event.end ?? event.at) - event.start) / 1000),
  });
}

// POSTs one alert. channel: {url, format, secret?}. With a secret the request carries X-Rettui-Timestamp (unix
// seconds) and X-Rettui-Signature: sha256= the HMAC-SHA256 of "<timestamp>.<body>". Resolves {ok: true} or
// {ok: false, error, retry}, where error is a short code: never the URL, the secret or the answer.
export async function sendWebhook(channel, event, text, { fetchFn = fetch, timeoutMs = WEBHOOK_TIMEOUT_MS, now = Date.now } = {}) {
  const body = webhookBody(channel.format, event, text);
  const headers = { 'User-Agent': 'rettui-status', 'Content-Type': channel.format === 'ntfy' ? 'text/plain; charset=utf-8' : 'application/json' };
  if (channel.format === 'ntfy') {
    // Fixed words: a header value must be plain ASCII.
    const cleared = event.type === 'recovered' || event.type === 'queue_cleared';
    const queue = event.type === 'queue_full' || event.type === 'queue_cleared';
    headers.Title = queue ? (cleared ? 'Announce queue is clear' : 'Announce queue is full') : cleared ? 'Entry point is back up' : 'Entry point is down';
    headers.Tags = cleared ? 'white_check_mark' : 'rotating_light';
  }
  if (channel.secret !== undefined) {
    // The time is signed with the body, so a captured request cannot be replayed later: the receiver
    // rejects a timestamp that is too old (see "Alerts" in the README).
    const timestamp = String(Math.floor(now() / 1000));
    headers['X-Rettui-Timestamp'] = timestamp;
    headers['X-Rettui-Signature'] = `sha256=${crypto.createHmac('sha256', channel.secret).update(`${timestamp}.${body}`).digest('hex')}`;
  }
  try {
    // A redirect is an error, not followed: it could lead the secret somewhere else.
    const res = await fetchFn(channel.url, { method: 'POST', body, headers, redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
    // The answer is never read: the body is dropped unread, which is the smallest size cap there is.
    await res.body?.cancel().catch(() => {});
    if (res.ok) return { ok: true };
    // A client error other than "too many" or "timed out" will not get better by trying again.
    return { ok: false, error: `http ${res.status}`, retry: res.status === 408 || res.status === 429 || res.status >= 500 };
  } catch (err) {
    return { ok: false, error: err?.name === 'TimeoutError' || err?.name === 'AbortError' ? 'timeout' : 'network', retry: true };
  }
}

export async function sendEmail(channel, event, text, options, mailFn = sendMail) {
  try {
    await mailFn(channel, { subject: alertSubject(event), text }, options);
    return { ok: true };
  } catch (err) {
    const code = typeof err?.message === 'string' && /^[a-z0-9 ]{1,40}$/.test(err.message) ? err.message : 'failed';
    // A refused address or a wrong password will not get better by trying again.
    return { ok: false, error: `smtp ${code}`, retry: !/^(reply 5\d\d|auth failed|tls failed|starttls)/.test(code) };
  }
}

export class Alerter {
  // The channels hold addresses and secrets: private, so no dump or JSON of the alerter shows them.
  #channels;
  #queue = [];
  #sending = 0;
  // Failed sends waiting for their next try. They hold no sending slot, so a dead channel does not starve the others.
  #retrying = 0;
  #stopped = false;
  #idle = [];

  // channels: [{type: 'webhook' | 'email', ...}]. names: Map of "host:port" to a display name.
  constructor({
    channels,
    events = EVENTS,
    cooldownMs = 15 * 60_000,
    repeatMs = 0,
    names = new Map(),
    now = Date.now,
    fetchFn = fetch,
    mailFn = sendMail,
    sleep = (ms) => new Promise((r) => setTimeout(r, ms).unref()),
    retryDelays = RETRY_DELAYS_MS,
    maxQueue = MAX_QUEUE,
    log = console.error,
    mailOptions,
    queueSamples = DEFAULT_QUEUE_SAMPLES,
  }) {
    this.#channels = channels.map((c) => ({ ...c }));
    this.events = new Set(events);
    this.cooldownMs = cooldownMs;
    this.repeatMs = repeatMs;
    this.names = names;
    this.now = now;
    this.fetchFn = fetchFn;
    this.mailFn = mailFn;
    this.sleep = sleep;
    this.retryDelays = retryDelays;
    this.maxQueue = maxQueue;
    this.log = log;
    this.mailOptions = mailOptions;
    // Per node: when the last down alert went out, whether the open incident was announced, and when it was last announced.
    this.state = new Map();
    // The announce queue rule (see createQueueWatch) and, per node, when the queue was announced full.
    this.queueWatch = createQueueWatch(queueSamples);
    this.queueState = new Map();
  }

  // One stats sample of a node: full is the node's own "an interface is at its limit". Once it has been
  // true for queueSamples samples in a row an alert goes out, and another when it clears. Nodes that report
  // no queue never get here. A node that went full again within the cooldown is not announced again, nor
  // its clearing, like a node that flaps. Never throws, never waits.
  observeQueue(key, { full, queued = null }, at = this.now()) {
    try {
      if (!this.events.has('announce_queue')) return;
      const result = this.queueWatch.observe(key, full ? 1 : 0, 1, at);
      const s = this.queueState.get(key) ?? { lastFull: -Infinity, quiet: false, start: at, queued: null };
      this.queueState.set(key, s);
      const name = this.names.get(key) ?? null;
      if (!result) {
        // A "full" held back by the cooldown is sent once the cooldown has passed and the queue is still full.
        if (s.quiet && full && at - s.lastFull >= this.cooldownMs) {
          s.quiet = false;
          s.lastFull = at;
          this.#enqueue({ type: 'queue_full', key, name, start: s.start, end: null, at, queued });
        }
        return;
      }
      if (result === 'full') {
        // The queue was full from the first sample of the run, not from the alert.
        s.start = this.queueWatch.since(key) ?? at;
        s.quiet = at - s.lastFull < this.cooldownMs;
        if (s.quiet) return;
        s.lastFull = at;
        this.#enqueue({ type: 'queue_full', key, name, start: s.start, end: null, at, queued });
      } else {
        const quiet = s.quiet;
        s.quiet = false;
        if (quiet) return;
        this.#enqueue({ type: 'queue_cleared', key, name, start: s.start, end: at, at });
      }
    } catch (err) {
      this.log(`alert: could not queue an alert (${err?.name ?? 'error'})`);
    }
  }

  // A stats fetch of a node failed: "in a row" needs every sample.
  queueMissed(key) {
    this.queueWatch.miss(key);
  }

  // Takes an event from the monitor: {type: 'down' | 'recovered', key, start, end, at}. Never throws, never waits.
  notify(event) {
    try {
      const e = { ...event, name: this.names.get(event.key) ?? null };
      const s = this.state.get(e.key) ?? { lastDown: -Infinity, quiet: false, lastSent: 0 };
      this.state.set(e.key, s);
      if (e.type === 'down') {
        // Flapping: a node that goes down again within the cooldown is not announced again, nor its recovery.
        s.quiet = e.at - s.lastDown < this.cooldownMs;
        if (s.quiet) return;
        s.lastDown = e.at;
        s.lastSent = e.at;
      } else {
        const quiet = s.quiet;
        s.quiet = false;
        if (quiet) return;
      }
      if (!this.events.has(e.type)) return;
      this.#enqueue(e);
    } catch (err) {
      this.log(`alert: could not queue an alert (${err?.name ?? 'error'})`);
    }
  }

  // Called after each round of checks with the open incidents ([[key, start]]). It does two things:
  // - a "down" that was held back by the cooldown (a node that flapped and then stayed down) is sent as soon as the
  //   cooldown since the last "down" alert has passed, because nothing else would ever announce it;
  // - with repeat_minutes, a reminder for a node that is still down and was announced.
  // An incident that was open before a restart has no state here yet: it starts one, and its reminders count from now.
  remind(open, time = this.now()) {
    for (const [key, start] of open) {
      let s = this.state.get(key);
      if (!s) {
        s = { lastDown: -Infinity, quiet: false, lastSent: time };
        this.state.set(key, s);
      }
      if (s.quiet) {
        if (time - s.lastDown < this.cooldownMs) continue;
        s.quiet = false;
        s.lastDown = time;
        s.lastSent = time;
        if (this.events.has('down')) this.#enqueue({ type: 'down', key, start, end: null, at: time, name: this.names.get(key) ?? null });
        continue;
      }
      if (this.repeatMs <= 0 || !this.events.has('down') || time - s.lastSent < this.repeatMs) continue;
      s.lastSent = time;
      this.#enqueue({ type: 'down', key, start, end: null, at: time, repeat: true, name: this.names.get(key) ?? null });
    }
  }

  #enqueue(event) {
    if (this.#stopped) return;
    const text = alertText(event, this.now());
    for (const channel of this.#channels) {
      if (this.#queue.length >= this.maxQueue) {
        // The oldest alert is the least useful one now.
        this.#queue.shift();
        this.log('alert: the alert queue is full, the oldest alert was dropped');
      }
      this.#queue.push({ channel, event, text });
    }
    this.#pump();
  }

  #pump() {
    while (this.#sending < MAX_SENDING && this.#queue.length > 0) {
      const job = this.#queue.shift();
      this.#sending++;
      this.#attempt(job)
        .catch((err) => this.log(`alert: sending failed (${err?.name ?? 'error'})`))
        .finally(() => {
          this.#sending--;
          this.#pump();
          this.#settle();
        });
    }
  }

  #settle() {
    if (this.#queue.length === 0 && this.#sending === 0 && this.#retrying === 0) for (const r of this.#idle.splice(0)) r();
  }

  // One try of one job. A failure that may get better is put back after its wait, with the slot given up meanwhile.
  async #attempt(job) {
    if (this.#stopped) return;
    const { channel, event, text, attempt = 1 } = job;
    const label = `${channel.type} channel ${this.#channels.indexOf(channel) + 1}`;
    let r;
    try {
      r =
        channel.type === 'email'
          ? await sendEmail(channel, event, text, this.mailOptions, this.mailFn)
          : await sendWebhook(channel, event, text, { fetchFn: this.fetchFn, now: this.now });
    } catch {
      r = { ok: false, error: 'failed', retry: true };
    }
    if (r.ok) return;
    const last = attempt >= MAX_ATTEMPTS || !r.retry;
    this.log(`alert: ${label} failed (${r.error})${last ? ', giving up' : `, try ${attempt + 1} of ${MAX_ATTEMPTS} follows`}`);
    if (last) return;
    this.#retrying++;
    Promise.resolve(this.sleep(this.retryDelays[Math.min(attempt - 1, this.retryDelays.length - 1)]))
      .catch(() => {})
      .then(() => {
        this.#retrying--;
        if (!this.#stopped) this.#queue.unshift({ channel, event, text, attempt: attempt + 1 });
        this.#pump();
        this.#settle();
      });
  }

  // Resolves when nothing is queued or being sent. For tests and for a clean stop.
  idle() {
    if (this.#queue.length === 0 && this.#sending === 0 && this.#retrying === 0) return Promise.resolve();
    return new Promise((r) => this.#idle.push(r));
  }

  // Drops what is waiting and stops retrying.
  stop() {
    this.#stopped = true;
    this.#queue.length = 0;
  }

  get queued() {
    return this.#queue.length;
  }
}

// The rule for "the announce queue stays full": a node's queue is full when its length
// is at or above its capacity, and an alert comes after `samples` full samples in a row.
// The monitor feeds it from each node's stats (the node says whether an interface is at its limit).
export function createQueueWatch(samples = 3) {
  const runs = new Map();
  return {
    // One stats sample of a node. Returns 'full' once, when the run reaches `samples`, and
    // 'cleared' when a queue that was reported full is below capacity again; else null.
    observe(key, length, capacity, at = null) {
      if (!Number.isFinite(length) || !Number.isFinite(capacity) || capacity <= 0 || length < 0) return null;
      const run = runs.get(key) ?? { count: 0, alerted: false, since: null };
      runs.set(key, run);
      if (length >= capacity) {
        if (run.count === 0) run.since = at;
        run.count++;
        if (run.count >= samples && !run.alerted) {
          run.alerted = true;
          return 'full';
        }
        return null;
      }
      const was = run.alerted;
      run.count = 0;
      run.alerted = false;
      return was ? 'cleared' : null;
    },
    // When the current run of full samples began (the time given with its first sample), or null.
    since(key) {
      return runs.get(key)?.since ?? null;
    },
    // A sample that failed to arrive breaks the run: "in a row" needs every sample.
    miss(key) {
      const run = runs.get(key);
      if (run && !run.alerted) run.count = 0;
    },
  };
}

// The alerter for the alerts section of the config (what loadConfigFile returns), or null without one.
export function createAlerter(settings, nodes = new Map(), options = {}) {
  if (!settings) return null;
  const names = new Map([...nodes].filter(([, n]) => n.name).map(([key, n]) => [key, n.name]));
  return new Alerter({ channels: settings.channels, events: settings.events, queueSamples: settings.queueSamples, cooldownMs: settings.cooldownMinutes * 60_000, repeatMs: settings.repeatMinutes * 60_000, names, ...options });
}
