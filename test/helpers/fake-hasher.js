import crypto from 'node:crypto';

// A stand-in for Argon2id, so that everything but the hash itself also runs on
// Node.js older than 24.7. It depends on every input, like the real one. The
// secret (the pepper) is mixed in only when there is one, so that hashes made
// before peppering still come out the same.
export const fakeHasher = async ({ password, salt, memory, passes, parallelism, length, secret = null }) => {
  const h = crypto.createHash('sha512').update(`${memory},${passes},${parallelism}|`).update(salt).update('|').update(password);
  if (secret !== null && secret.length > 0) h.update('|secret|').update(secret);
  return h.digest().subarray(0, length);
};
