// An SMTP server on loopback for the tests: SMTPS or STARTTLS, optional AUTH, and a
// log of what the client sent. The key below is a throwaway made for these tests
// (a self-signed certificate for localhost and 127.0.0.1); it protects nothing.
import net from 'node:net';
import tls from 'node:tls';

export const CERT = `-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIUKE4ZrgBD+yFXU+C9XFbwIAtQPTUwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTExOTIyMzg0OFoYDzIxMjYxMDI2
MjIzODQ4WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATYrhkz0mW6yIoOkYea5EcTekAGZSoH+CPaU3dPb/bEIin1hjvoFOdU
zfaARBKqLgbFiLy8P09txrwjy9ZEMpuro28wbTAdBgNVHQ4EFgQUVBfpuxUu7Tnj
bRV8rjig8GY9qcUwHwYDVR0jBBgwFoAUVBfpuxUu7TnjbRV8rjig8GY9qcUwGgYD
VR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZI
zj0EAwIDSAAwRQIgKjEV0hLk+MetjRGQy1faTUfUUve7n+RxbDFK/7c3geMCIQD0
SunsJNJELBK6UiWrAaL2dLOsUJJm1DP0vVr0xX9dhA==
-----END CERTIFICATE-----`;

export const KEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg820PiiOqd6DZQFrr
7HBty8EHB/a/ckBXEbg9LTo7Px6hRANCAATYrhkz0mW6yIoOkYea5EcTekAGZSoH
+CPaU3dPb/bEIin1hjvoFOdUzfaARBKqLgbFiLy8P09txrwjy9ZEMpur
-----END PRIVATE KEY-----`;

// The options that make a client trust the test certificate.
export const TRUST = { ca: CERT };

// opts: {mode: 'tls' | 'starttls', starttls: offer STARTTLS (default true), auth: {user, pass} or null,
// hang: never answer after the greeting, rcptReply: code for RCPT, bigReply: send a huge greeting,
// authReply: code for the AUTH answer, inject: send an extra reply in the same write as the answer to STARTTLS}.
export async function fakeSmtp(opts = {}) {
  const { mode = 'starttls', starttls = true, auth = null, hang = false, rcptReply = 250, bigReply = false, inject = false } = opts;
  const log = { commands: [], messages: [], auths: [] };
  const handle = (socket0) => {
    let socket = socket0;
    let buffer = '';
    let data = null;
    let secure = mode === 'tls';
    let login = null;
    socket0.on('error', () => {});
    const say = (text) => socket.write(`${text}\r\n`);
    const onData = (chunk) => {
      buffer += chunk.toString('utf8');
      for (;;) {
        if (data !== null) {
          const end = buffer.indexOf('\r\n.\r\n');
          if (end < 0) return;
          log.messages.push(buffer.slice(0, end + 2));
          buffer = buffer.slice(end + 5);
          data = null;
          say('250 queued');
          continue;
        }
        const i = buffer.indexOf('\r\n');
        if (i < 0) return;
        const line = buffer.slice(0, i);
        buffer = buffer.slice(i + 2);
        command(line);
      }
    };
    const command = (line) => {
      if (login) {
        log.auths.push(['login', Buffer.from(line, 'base64').toString()]);
        if (login === 'user') {
          login = 'pass';
          return say('334 UGFzc3dvcmQ6');
        }
        login = null;
        const ok = auth && log.auths.at(-2)[1] === auth.user && log.auths.at(-1)[1] === auth.pass;
        return say(ok ? '235 ok' : '535 no');
      }
      log.commands.push(line.startsWith('AUTH') ? line.split(' ').slice(0, 2).join(' ') : line);
      const [verb] = line.split(' ');
      if (verb === 'EHLO') {
        const lines = ['localhost', '8BITMIME'];
        if (mode === 'starttls' && !secure && starttls) lines.push('STARTTLS');
        if (auth && secure) lines.push('AUTH PLAIN LOGIN');
        return say(lines.map((l, n) => `250${n === lines.length - 1 ? ' ' : '-'}${l}`).join('\r\n'));
      }
      if (verb === 'STARTTLS') {
        say(inject ? '220 go ahead\r\n250 fake' : '220 go ahead');
        socket.removeAllListeners('data');
        const wrapped = new tls.TLSSocket(socket, { isServer: true, key: KEY, cert: CERT });
        wrapped.on('error', () => {});
        wrapped.on('data', onData);
        socket = wrapped;
        secure = true;
        buffer = '';
        return;
      }
      if (verb === 'AUTH') {
        const [, method, rest] = line.split(' ');
        if (method === 'PLAIN') {
          const [, user, pass] = Buffer.from(rest ?? '', 'base64').toString().split('\0');
          log.auths.push(['plain', user, pass]);
          return say(auth && user === auth.user && pass === auth.pass ? '235 ok' : '535 no');
        }
        login = 'user';
        return say('334 VXNlcm5hbWU6');
      }
      if (verb === 'MAIL') return say('250 ok');
      if (verb === 'RCPT') return say(rcptReply === 250 ? '250 ok' : `${rcptReply} no`);
      if (verb === 'DATA') {
        data = '';
        return say('354 go');
      }
      if (verb === 'QUIT') {
        say('221 bye');
        return socket.end();
      }
      return say('500 what');
    };
    if (bigReply) return socket.write(`220 ${'x'.repeat(40 * 1024)}\r\n`);
    socket.on('data', onData);
    say('220 localhost ready');
    if (hang) {
      socket.removeAllListeners('data');
    }
  };
  const server = mode === 'tls' ? tls.createServer({ key: KEY, cert: CERT }, handle) : net.createServer(handle);
  server.on('tlsClientError', () => {});
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { port: server.address().port, log, close: () => new Promise((r) => (server.closeAllConnections?.(), server.close(r))) };
}
