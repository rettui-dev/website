## The user store

The users made on the website, and the second factor of every user, are kept in `users.db` in
`DATA_DIR`, a SQLite database (Node.js's built-in `node:sqlite`). The server and
`scripts/users.js` can both use it at the same time.

**What the key protects.** The user store has a key, which you make and keep apart from the data:

- **Passwords are peppered.** A password hash is made with the key mixed in (the "pepper"), so a
  stolen `users.db` alone is no use for guessing passwords: without the key, no guess can be
  checked. Each hash records which key version made it (`keyid` in the hash).
- **TOTP secrets are encrypted** (AES-256-GCM), each tied to its user, so the secrets of the
  authenticator apps cannot be read from the file, or moved to another user.
- **Recovery codes** are kept as a keyed hash (HMAC) of the code.

From the key three separate keys are derived, one for each of these. The key is never stored in
the database; only a short check value is, so that a wrong key is noticed at start.

Passwords that were in the store before it had a key (imported from `users.json`) have no pepper
yet. They keep working, and each is peppered the next time its user signs in. **Users in the
config file are never peppered**, because the server cannot rewrite that file: protect the config
file as before, and move admins into the store to give them the pepper (see [Moving users out of
the config file](Managing-Users)). Their second factor, kept in the store, is encrypted like everyone's.

**Signing in with a passkey alone changes nothing in the store.** It finds the user from the credential id and the user handle the store already keeps, so there is no new field and no new schema version (see [Passkeys](Accounts-and-Second-Factor#passkeys)).

**Users' LXMF alert addresses change nothing in the schema either.** A user's own LXMF address (see
[Uptime and alerts](Uptime-and-Alerts#alerts)), whether it is confirmed and the node alerts tick are
one row of the `meta` table each, under the key `lxmf|store|<name>` (`lxmf|config|<name>` for a user
in the config file), holding a short JSON text. The schema version and every table are as before,
so an older release opens the database and ignores these rows. A row also holds the user's creation
time, and is read only for the user it was made for: if an older release deletes a user, the row it leaves
behind is not given to a new user of the same name. A row that cannot be read is no address, never an
unreadable store. The address is not secret, so it is stored as plain text; it is in backups of
`users.db` like everything else in it.

**What the key does not protect.**

- **The pepper protects reading, not writing.** Someone who can only read `users.db` learns
  nothing they can use. Someone who can **write** to it (or to the data directory) can put in a
  password hash or a user of their own and take over accounts, key or not. Keep the data
  directory writable by the server's user only.
- **`users.json` and old backups.** A `users.json` from an older version holds the second-factor
  secrets unencrypted and password hashes without a pepper, as they were at the import. It stays
  in the data directory until you retire it (see "From users.json"), and every backup of the data
  directory or volume made before that holds it too. Treat those backups as secret, and delete
  them when they are no longer needed.
- **Key and data seen together.** Whoever has the key and a copy of the data has everything the
  key protects, and changing the key (see "Changing the key") does not help against them: they
  already have the secrets. Then also reset every user's second factor (`reset-2fa`, after which
  they set up two-step sign-in again and get new recovery codes) and password (`reset-password
  NAME --generate`).

### The user store key

The key is needed as soon as there are users, in the config file or in the store: without it the
server does not start, and says to set `USERS_KEY_FILE` and that `node scripts/users.js gen-key`
makes one. A site without logins needs no key.

Give it in a file, `USERS_KEY_FILE` (a path), or inline in `USERS_KEY` (not both; the file is
safer). The file has one line per key version, `VERSION:KEY`:

    # The user store key. Keep it out of the data directory and its backups.
    1:KEY-OF-43-CHARACTERS-FROM-GEN-KEY

`VERSION` is a number from 1 to 65535, and `KEY` 32 random bytes in base64url (43 characters).
Entries can also be separated by commas (handy for `USERS_KEY`), and `#` starts a comment. At
most 16 entries, and the file at most 4 KiB. The highest version is the current one: new
passwords, TOTP secrets and recovery codes use it. The others are only read.

When you run `scripts/users.js` as root, it works as the owner of the data directory (see
[Managing users](Managing-Users#managing-users)), so the key file must be readable by that user (or one of their groups), like
it is for the server.

**Making one.** `node scripts/users.js gen-key` prints a new line, `1:...`; `--version N` gives
another version (for a new key, see "Changing the key"). It only prints; the store is not read.

    mkdir -p secrets
    (umask 077; node scripts/users.js gen-key > secrets/users.key)

Without Node.js on the host, use the image (`-T`, so that only the key line goes to the file):

    (umask 077; docker compose run --rm -T --no-deps website node scripts/users.js gen-key > secrets/users.key)

**In Docker**, give the file to the container as a secret, in `compose.yaml`:

    services:
      website:
        environment:
          USERS_KEY_FILE: /run/secrets/users_key
        secrets:
          - users_key
    secrets:
      users_key:
        file: ./secrets/users.key

Compose mounts the file as it is, with its owner and mode, at `/run/secrets/users_key`. The
server runs as uid 1000, so make the file that user's and readable by nobody else:

    sudo chown 1000 secrets/users.key
    sudo chmod 400 secrets/users.key

(If the container runs as another user, `user:` in `compose.yaml`, give the file to that uid.)

**Keep the key outside the data directory**, and so outside the data volume: whoever has a copy
of the data and the key has everything the key protects. The server and the command line warn at
start when `USERS_KEY_FILE` lies inside `DATA_DIR`, or can be read by other users.

**Losing the key** makes every TOTP secret and every peppered password in the store unusable;
nothing can bring them back. Keep a copy of the key file somewhere safe, apart from the backups
of the data (see "Backups").

### Backups

Back up the database and the key **separately**:

- **The database:** `node scripts/users.js backup FILE` writes a consistent copy of the store to
  `FILE`, a new file (it never writes over one, nor through a link), with mode 0600, while the
  server runs. It is made in a new private folder next to `FILE`, checked to be the very copy it
  made (yours, mode 0600), and then put in place, so a failure leaves nothing behind. A folder
  other users can write to is refused (unless it has the sticky bit, as `/tmp` has). Do not copy `users.db` itself while the server runs: the newest
  changes may still be in `users.db-wal`. Keep backups out of the repository and out of the
  image: write them to a folder of their own outside the repository, such as `~/backups`
  (`backups/`, `*.db`, `*.db-wal` and `*.db-shm` are in `.gitignore` and `.dockerignore` in case
  one ends up there anyway). In Docker, write it into the data volume and copy it out:

      mkdir -p ~/backups && chmod 700 ~/backups
      docker compose exec website node scripts/users.js backup /data/users-backup.db
      docker compose cp website:/data/users-backup.db ~/backups/users-$(date +%F).db
      docker compose exec website rm /data/users-backup.db

- **The key file**, kept somewhere else (a password manager, an offline copy).

To restore, stop the server, move `users.db`, `users.db-wal` and `users.db-shm` away, put the
backup in their place as `users.db` (owned by the server's user, mode 0600), and start with the
same key. **A backup without its key** loses everyone's TOTP secret and every peppered password:
the server does not start with the wrong key, and without one at all. To recover from that, make a
new key, move the old `users.db*` away, make a new admin with `scripts/users.js create`, and have
users made again, or start from a `users.json` (see "From users.json"). A `users.json` is the
store as it was at the import, long ago perhaps: it brings back users deleted since, and old
passwords and second factors. After any import of an old `users.json`, check the users
(`scripts/users.js list`), delete those that should be gone, and reset everyone's two-step
sign-in (`reset-2fa`) and password (`reset-password NAME --generate`).

`node scripts/users.js check` checks the database (SQLite's `quick_check`), that its schema is
exactly the one this version makes (no other tables or columns, no triggers or views), and the
key, and says what each key version still protects; run it after a restore, or now and then.

### Changing the key

Rotate the key when it may have been seen by someone else, or now and then:

1. Add a new line with the next version to the key file, keeping the old line:
   `(umask 077; node scripts/users.js gen-key --version 2 >> secrets/users.key)`.
2. Restart the server. It records version 2 in the store when it starts, and new passwords, TOTP
   secrets and recovery codes now use it. Until then `scripts/users.js` keeps using version 1,
   so that the running server can read what it writes, and `rekey` refuses: "Restart the
   website first".
3. Run `node scripts/users.js rekey` (in Docker: `docker compose exec website node
   scripts/users.js rekey`). It encrypts every TOTP secret again with the new key, and prints
   what each version still protects, for example "version 1: 3 password hashes (upgraded at next
   sign in), 12 recovery codes (replaced when used or regenerated), 0 TOTP secrets; still
   needed, keep it in the key file".
4. Remove the old line only when `node scripts/users.js check` says "version 1: unused; it can
   be removed from the key file". Password hashes move to the new key when their user signs in,
   and recovery codes when they are used or new ones are made, so this can take a while; a reset
   (`reset-password --generate`, or new recovery codes) moves them at once. Removing a version
   that is still needed makes the server stop at start with "the user store needs key version
   1; it is not in USERS_KEY_FILE": put the line back.

Rotating the key keeps a key that leaks later from opening what was in the store before, but it
does not help if the old key and a copy of the data were seen together: see "What the key does
not protect".

The store keeps a check value for each key version it uses, so that a wrong key is noticed. A
store that has users but no check value at all, or whose data uses a version without its check
value (something removed them), is refused at start, with the right key as with a wrong one:
restore it from a backup.

### Where to keep it

Keep `/data` on a **named local volume** (as `compose.yaml` does) or a local disk. The store uses
SQLite's write-ahead log, which needs shared memory between the server and the command line:
never put it on NFS, SMB or any volume shared between hosts, where it can be damaged. Run one
server per store.

The server makes `users.db` with mode 0600, and SQLite makes `users.db-wal` and `users.db-shm`
next to it with the same mode. Keep all three together: moving or copying `users.db` alone loses
recent changes. The server also writes `user-store.created` and keeps it: the time the first
store was made in this data directory, and a second line once a store here had users. That is
how a later import of `users.json` into a new store is noticed as a step back (see "From
users.json"). Moving `users.db*` away leaves it, as it should.

### From users.json

Older versions kept the users in `users.json`. At its first start (or the first
`scripts/users.js` command), this version imports `users.json` into a new `users.db`, once, in
one transaction: TOTP secrets are encrypted, recovery codes keyed, passwords stay unpeppered
until their next sign in. It needs the key if `users.json` has users. A `users.json` that
cannot be read (or is a link, or not a plain file) stops the start and is left as it is; nothing
is made. `users.json` itself is never changed or removed by the server, and is not read again: a
warning at start says when it was changed after the import. Fields this version does not keep
are dropped and named in a warning (names that do not look like field names are only counted).

**Retire it after the import.** `users.json` still holds the second-factor secrets unencrypted and
password hashes without a pepper. As long as it is in the data directory, every start warns
about it. Once the import worked (and you have a backup of the store), run `node scripts/users.js
retire-users-json`: it checks that `users.json` is the very file that was imported, and renames
it to `users.json.imported` with mode 0600 (it refuses a changed file or an existing
`users.json.imported`). Every start warns while `users.json.imported` is in the data directory
too: move it to offline storage, or delete it. `retire-users-json --delete` deletes instead of
renaming, after the same check: `users.json`, or `users.json.imported` once it was renamed.
Deleting does not wipe the disk blocks it was on, and backups of the data directory made before
then still hold it.

**Importing it again** brings the old snapshot back. Moving `users.db*` away and starting imports
`users.json` again into a new store: every user deleted since comes back, with the password and
second factor they had then. The server warns loudly when a store with users had been made in
the data directory before ("users.json is the snapshot of an older import"), and the audit line
has `again: true`. A first import after a start without users (users.json put in place later) is
not warned about. After that, check the users, delete those that should be gone, and reset every
password and two-step sign-in. A `users.json` with users that was never imported (put there after
the store was made) stops the start when neither the store nor the config file has users, since
the site would otherwise run without sign-in: move it away, or move `users.db*` away to import it.

**Going back to an older version** reads `users.json`, which is the store as it was at the import:
every change made since (new users, passwords, second factors) is lost there, and users deleted
since are back. Rename `users.json.imported` back to `users.json` for that, and reset passwords
and two-step sign-in afterwards as above. An older version
also does not know `users.db`, the key or the pepper.

`users.lock`, which older versions kept in `DATA_DIR`, is no longer used and can be removed, and
the 8 MiB limit on `users.json` applies only to the import now.
