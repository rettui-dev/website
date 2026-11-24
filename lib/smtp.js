// A small SMTP client for alert mail, on node:net and node:tls. It sends one
// plain text message over a connection that is encrypted and whose certificate
// is checked: SMTPS from the first byte ("tls"), or STARTTLS ("starttls"), which
// is required and never skipped. Errors are short codes that never carry the
// server's words, the user name or the password.
import net from 'node:net';
import tls from 'node:tls';
import crypto from 'node:crypto';

export const SMTP_TIMEOUT_MS = 20_000;
// What is read from the server at most for one reply, and what is sent as the message at most.
export const MAX_REPLY_BYTES = 16 * 1024;
export const MAX_MESSAGE_BYTES = 16 * 1024;

class SmtpError extends Error {}
const fail = (code) => {
  throw new SmtpError(code);
};

// Text that goes into a header or a command must be one line.
const LINE_BREAK_RE = /[\r\n\0]/;
export function oneLine(value, what) {
  if (typeof value !== 'string' || LINE_BREAK_RE.test(value)) throw new SmtpError(`${what} has a line break`);
  return value;
}

// An address as it goes into <...>: one line, no brackets, spaces, quotes or commas.
export const ADDRESS_RE = /^[^\s<>@,;:"()[\]\\]{1,64}@[A-Za-z0-9]([A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$/;
export function address(value, what) {
  oneLine(value, what);
  if (value.length > 254 || !ADDRESS_RE.test(value)) throw new SmtpError(`${what} is not an email address`);
  return value;
}

// A header value: plain ASCII stays as it is, anything else is sent as one RFC 2047 word.
export function headerText(value, what) {
  oneLine(value, what);
  if (/^[\x20-\x7e]*$/.test(value)) return value;
  return `=?UTF-8?B?${Buffer.from(value, 'utf8').toString('base64')}?=`;
}

// The message with CRLF line ends, as it is sent after DATA (without the final dot line).
export function buildMessage({ from, to, subject, text, date = new Date(), id = crypto.randomBytes(12).toString('hex') }) {
  const domain = address(from, 'from').split('@')[1];
  const body = Buffer.from(String(text).replace(/\r\n?|\n/g, '\n'), 'utf8').subarray(0, MAX_MESSAGE_BYTES).toString('base64');
  const lines = body.match(/.{1,76}/g) ?? [];
  const head = [
    `From: ${from}`,
    `To: ${to.map((t) => address(t, 'to')).join(', ')}`,
    `Subject: ${headerText(subject, 'subject')}`,
    `Date: ${date.toUTCString().replace('GMT', '+0000')}`,
    `Message-ID: <${id}@${domain}>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: base64',
    'Auto-Submitted: auto-generated',
  ];
  // Base64 has no dots at the start of a line to stuff.
  return `${head.join('\r\n')}\r\n\r\n${lines.join('\r\n')}\r\n`;
}

// Reads replies one at a time. A reply is lines "250-..." and a last line "250 ...".
class Replies {
  #socket;
  #buffer = '';
  #waiting = null;
  #closed = null;

  constructor(socket) {
    this.#socket = socket;
    this.attach(socket);
  }

  attach(socket) {
    this.#socket = socket;
    // Nothing read before this point may be taken for an answer on the connection now being attached.
    this.#buffer = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk) => {
      this.#buffer += chunk;
      if (this.#buffer.length > MAX_REPLY_BYTES) {
        this.#buffer = '';
        this.#end(new SmtpError('reply too large'));
        socket.destroy();
      } else this.#flush();
    });
    socket.on('error', () => this.#end(new SmtpError('connection failed')));
    socket.on('close', () => this.#end(new SmtpError('connection closed')));
  }

  #end(err) {
    this.#closed ??= err;
    if (this.#waiting) this.#flush();
  }

  #flush() {
    if (!this.#waiting) return;
    const lines = [];
    let rest = this.#buffer;
    for (;;) {
      const i = rest.indexOf('\n');
      if (i < 0) break;
      const line = rest.slice(0, i).replace(/\r$/, '');
      rest = rest.slice(i + 1);
      const m = /^(\d{3})([ -])/.exec(line);
      if (!m) {
        this.#buffer = rest;
        return this.#settle(new SmtpError('bad reply'));
      }
      lines.push(line);
      if (m[2] === ' ') {
        this.#buffer = rest;
        return this.#settle(null, { code: Number(m[1]), lines: lines.map((l) => l.slice(4)) });
      }
    }
    if (this.#closed) this.#settle(this.#closed);
  }

  #settle(err, value) {
    const w = this.#waiting;
    this.#waiting = null;
    if (err) w.reject(err);
    else w.resolve(value);
  }

  // Are there bytes that came after the last complete reply?
  get pending() {
    return this.#buffer.length > 0;
  }

  // The next reply.
  next() {
    return new Promise((resolve, reject) => {
      this.#waiting = { resolve, reject };
      this.#flush();
    });
  }

  send(line) {
    this.#socket.write(`${line}\r\n`);
  }
}

// Sends one message. cfg: {host, port, security: 'tls' | 'starttls', username?, password?, auth?: 'plain' | 'login',
// from, to: [...]}. mail: {subject, text}. options: {timeoutMs, tlsOptions} (the second is for tests only, to trust a test
// certificate). Resolves on success; rejects with an Error whose message is a short code.
export async function sendMail(cfg, mail, { timeoutMs = SMTP_TIMEOUT_MS, tlsOptions = {}, now = () => new Date() } = {}) {
  // Checked before anything is sent: a line break in any field is refused, not cleaned.
  const from = address(cfg.from, 'from');
  const to = cfg.to.map((t) => address(t, 'to'));
  const message = buildMessage({ from, to, subject: mail.subject, text: mail.text, date: now() });
  const user = cfg.username === undefined ? null : oneLine(cfg.username, 'username');
  const password = cfg.password === undefined ? null : oneLine(cfg.password, 'password');
  const servername = net.isIP(cfg.host) ? undefined : cfg.host;
  const tlsSettings = { servername, minVersion: 'TLSv1.2', rejectUnauthorized: true, ...tlsOptions };

  let socket = null;
  let timer;
  const work = (async () => {
    try {
      socket = await connect(cfg, tlsSettings);
    } catch (err) {
      if (err instanceof SmtpError) throw err;
      return fail(cfg.security === 'tls' ? 'tls failed' : 'connect failed');
    }
    const r = new Replies(socket);
    const expect = async (ok, code) => {
      const reply = await r.next();
      if (!ok.includes(reply.code)) fail(code ?? `reply ${reply.code}`);
      return reply;
    };
    const command = async (line, ok, code) => {
      r.send(line);
      return expect(ok, code);
    };
    await expect([220]);
    let ehlo = await command('EHLO localhost', [250]);
    if (cfg.security === 'starttls') {
      if (!ehlo.lines.some((l) => /^STARTTLS$/i.test(l))) fail('starttls not offered');
      await command('STARTTLS', [220], 'starttls refused');
      // Bytes that came with the 220 were sent before the encryption: a man in the middle could have put an
      // answer there for the next command to find. Nothing may be left over.
      if (r.pending) fail('starttls failed');
      socket.removeAllListeners('data');
      socket.removeAllListeners('error');
      socket.removeAllListeners('close');
      // The TLS layer reports its own errors; this keeps a late one on the bare socket from being unhandled.
      socket.on('error', () => {});
      try {
        socket = await upgrade(socket, tlsSettings);
      } catch {
        return fail('tls failed');
      }
      r.attach(socket);
      ehlo = await command('EHLO localhost', [250]);
    }
    if (user !== null) {
      if (password === null) fail('no password');
      if (cfg.auth === 'login') {
        await command('AUTH LOGIN', [334], 'auth failed');
        await command(Buffer.from(user).toString('base64'), [334], 'auth failed');
        await command(Buffer.from(password).toString('base64'), [235], 'auth failed');
      } else {
        await command(`AUTH PLAIN ${Buffer.from(`\0${user}\0${password}`).toString('base64')}`, [235], 'auth failed');
      }
    }
    await command(`MAIL FROM:<${from}>`, [250]);
    for (const t of to) await command(`RCPT TO:<${t}>`, [250, 251]);
    await command('DATA', [354]);
    r.send(`${message}.`);
    await expect([250]);
    // The mail is accepted; whether QUIT is answered does not matter.
    r.send('QUIT');
  })();
  const limit = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new SmtpError('timeout')), timeoutMs);
    timer.unref();
  });
  try {
    await Promise.race([work, limit]);
  } finally {
    clearTimeout(timer);
    socket?.destroy();
    // The work may still be waiting on a reply that never comes; its failure is no longer news.
    work.catch(() => {});
  }
}

function connect(cfg, tlsSettings) {
  return new Promise((resolve, reject) => {
    const s = cfg.security === 'tls' ? tls.connect({ host: cfg.host, port: cfg.port, ...tlsSettings }) : net.connect({ host: cfg.host, port: cfg.port });
    s.once(cfg.security === 'tls' ? 'secureConnect' : 'connect', () => {
      s.removeListener('error', reject);
      resolve(s);
    });
    s.once('error', reject);
  });
}

function upgrade(socket, tlsSettings) {
  return new Promise((resolve, reject) => {
    const s = tls.connect({ socket, ...tlsSettings });
    s.once('secureConnect', () => {
      s.removeListener('error', reject);
      resolve(s);
    });
    s.once('error', reject);
  });
}
