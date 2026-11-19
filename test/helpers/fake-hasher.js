import crypto from 'node:crypto';

// A stand-in for Argon2id, so that everything but the hash itself also runs on
// Node.js older than 24.7. It depends on every input, like the real one.
export const fakeHasher = async ({ password, salt, memory, passes, parallelism, length }) => {
  const h = crypto.createHash('sha512').update(`${memory},${passes},${parallelism}|`).update(salt).update('|').update(password).digest();
  return h.subarray(0, length);
};
