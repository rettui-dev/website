// Stops early, with a plain message, when Node is too old. The site needs
// crypto.argon2 and node:sqlite, so on older versions tests fail in odd ways.
const [major, minor] = process.versions.node.split('.').map(Number);
if (major < 24 || (major === 24 && minor < 7)) {
  console.error(`This site needs Node.js 24.7 or later; this is ${process.versions.node}. Run it with Node 24 (see .nvmrc).`);
  process.exit(1);
}
