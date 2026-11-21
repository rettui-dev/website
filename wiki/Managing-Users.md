## Managing users

Admins (role `admin`) manage users on the **Users** page, `/users`. The Account page shows a
"Manage users" link to admins only. For everyone else (signed out, `manage`, `viewer`, or an
admin who still has to change a password an admin set) `/users` answers 404 and `/api/users`
401 or 403: the server decides, not the page.

**What the page shows.** Every user: name, role, where they come from (config file or website),
what two-step sign-in is made of ("Off", or "On" with "app code" and the number of passkeys, like "On:
app code, 2 passkeys"), how many known devices, last sign in and when they were made. No
password, hash, secret, passkey id or device id is ever sent. On a phone the table becomes one card per user.

**What an admin can do.**

- **Add a user** (website users only): a name (1 to 32 letters, digits, `.`, `-`, `_`), a role
  (`admin`, `manage` or `viewer`), and a first password. Either the admin types one (12+
  characters, the same rules as a password change), or the page makes a one-time password (20
  random letters and digits) and shows it once, with a Copy button: it is never shown again, not
  stored anywhere but as a hash, and not logged. Either way the new user must choose their own
  password when they first sign in.
- **Change the role** of a website user: anyone may be made an admin, but another admin is not
  demoted here (see below). An admin may give themselves another role.
- **Reset the password** of a website user: a one-time or typed password, as above, which they
  must change at their next sign in. An admin changes their own password on the Account page.
- **Reset two-step sign-in**, for someone who lost their phone or security key: it turns the app
  code off, removes every passkey and the recovery codes, and forgets every known device. The
  dialog names what will go ("app code, 2 passkeys, recovery codes and known devices"). This works for users in the config file too.
  An admin turns their own off on the Account page.
- **Delete** a website user who is not an admin (see below). An admin may delete themselves.

**Admins are reset, demoted and deleted on the server only.** The password and the two-step
sign-in of an admin (another admin, or one from the config file) cannot be reset on the Users
page: an admin who could do that could sign in as the other admin. For the same reason another
admin cannot be given a lower role there either (else: demote them, reset them, make them an
admin again), and cannot be deleted there, so that one admin cannot lock another out. The page
does not offer those actions on another admin's row, and says where they are done. The API
answers 403 and writes a line to `audit.log`, with who tried:

- a reset: "Admin accounts can only be reset from the command line on the server
  (scripts/users.js reset-password or reset-2fa).", event `admin-reset-refused`;
- a demotion: "Admins can only be demoted from the command line on the server (scripts/users.js
  set-role).", event `admin-demote-refused`;
- a deletion: "Admins can only be deleted from the command line on the server (scripts/users.js
  delete).", event `admin-delete-refused`.

This holds also when the user is made an admin while the request is under way: the store checks
the role again, on the record as it is then, right before it writes. Someone with access to the
server does these with `node scripts/users.js reset-password <name>`,
`node scripts/users.js reset-2fa <name>`, `node scripts/users.js set-role <name> <role>` or
`node scripts/users.js delete <name>` (see "The command line" below). An admin may still give
themselves another role, or delete themselves, while another admin exists (see "The last admin").
Give the admin role only to people you trust with every account.

Every way of writing the page's address (`/users.html`, `/users.html/`, `/%75sers.html`,
`/users%2ehtml`, other cases) goes through the same check as `/users`, and every way of writing
`/account.html` is the account page.

Each change to a user signs that user out everywhere, ends their open second steps and forgets
their known devices. Destructive changes ask in a dialog first, saying what will happen.

**Users in the config file** are read-only here, marked "Managed by config": their name,
password and role are changed in the config file. Only their second factor can be reset, and
only if they are not an admin.

**The last admin.** The last admin (counting the config file's admins too) can never be deleted
or given another role, also not by themselves. An admin may give themselves another role, or
delete themselves, only while another admin exists; they are then signed out at once.

**Safeguards.** Every change needs, all at once: an admin's session; a sign in from the last 15
minutes; while any node has a `manage_url` (see [Managing nodes](Managing-Nodes#managing-nodes)), the admin's two-step sign-in
turned on (else the answer is 403 with `code: "second-factor-required"` and the page says to turn it
on first: otherwise an admin's password alone would be enough to make a `manage` user, set up a
second factor for it, and change nodes through it), and not inside the 24-hour wait after their own
first second factor (else 403 with `code: "second-factor-new"`, asked again after the password; see
[The wait after a first second factor](Managing-Nodes) under [Managing nodes](Managing-Nodes#managing-nodes)); the admin's password in the request itself, and with their two-step sign-in on their
passkey, a current code from their app or a recovery code as well, asked for in the step-up dialog (see
[Changes need a recent sign in](Accounts-and-Second-Factor)); the request header, same origin and JSON,
as for the account API (`POST /api/users/create`, `/role`, `/delete`, `/reset-password`,
`/reset-second-factor`, at most 16 KiB). Each admin may make 30 changes an hour, wrong passwords
and codes included (then 429 with `Retry-After`); a request that is refused before any password
is asked (an unknown user, a bad name) does not count, except a reset of an admin's password or
two-step sign-in, or another admin's demotion or deletion, which is refused with 403 before any password is
asked and does count, so that refusals cannot fill `audit.log`. Neither does one answered 503 because
too many passwords were being checked at once (the admin's own requests in parallel, say). After every step the server checks that
the admin's session is still there and still an admin's, and the store checks it again right
before it writes: an admin signed out or demoted meanwhile gets 401 and nothing changes. Each
change is an audit line with the admin and the user (see [Audit log](Accounts-and-Second-Factor)).

**First sign in with a password an admin set.** The sign in works, and the answer says
`mustChangePassword: true`; the header sends the user to the Account page, which shows only the
password change. Until they choose a new password, the session can only change the password and
sign out: the status page shows them what a visitor sees, and every other account or users change
answers 403.

**The first admin.** There is no "first user becomes admin". With no admin anywhere, the Users
page does not exist. Make one in either way:

- give a user in the config file `role: admin` and restart the server, or
- run `node scripts/users.js create NAME --role admin` (it asks for the password twice without
  showing it, or reads it from stdin). It needs the user store key first (see [The user store
  key](User-Store#the-user-store-key)). The server may be running: it picks the new user up within a second. But the server
  turns sign-in on only when it starts with users, so if it was started without any (or without
  a key), the command says "restart the website to turn on sign-in": restart it once. In Docker:
  `docker compose exec website node scripts/users.js create NAME --role admin`. That runs in the
  running container, as the image's `node` user like the server, with its data volume and its
  key. With the site stopped, `docker compose run --rm website node scripts/users.js ...` does
  the same.

**Run as root** (outside Docker, say), the command first becomes
the owner of the data directory (the server's user, with that user's groups), before it opens
anything, the key file included, and says so: the files it makes are then that user's, and
nothing that user can put in the data directory (a link in place of `users.db-wal`, say) can make
root write to or take over a file elsewhere. So **the key file must be readable by the owner of
the data directory** (directly or through one of their groups), as it is for the server; if it
is not, the command says so and does nothing. A backup is written as that user too, into a
folder they can write to. It works on the data directory by its real path (links resolved), and
refuses, changing nothing, when another user could change the way there meanwhile:

- a folder on the way belongs to a user other than root and the owner of the data directory, or
  others can write to it (unless it has the sticky bit and is root's, as `/tmp` is);
- the path goes through a link that is not root's, or lies in a folder that is not root's;
- the data directory does not exist yet, and others can write where it would be made;
- the data directory is root's and others can write to it (unless it has the sticky bit).

Only when root owns the data directory does the command stay root, and then it warns that the
new `users.db` is root's and a server running as another user cannot open it.

**The command line, `scripts/users.js`.** It works on the user store with the same rules as the
website (names, roles, password rules, the last admin), and needs the same key as the server
(`USERS_KEY_FILE` or `USERS_KEY`). It may run while the server runs: each change is one short
transaction, the password is hashed (with the pepper of the current key) before it starts, and a
running server picks the change up within a second and signs that user out. If the server is
writing at that moment, the command waits up to 10 seconds; after that it says "Another program
is changing the user store; nothing was changed. Try again." A store that cannot be read is left
as it is and nothing is done. The command makes `users.db` only for `create`, or to import a
`users.json`: any other command in a data directory without a store says so and makes nothing
(`list` says "No users"), so a mistyped `--data-dir` does not leave an empty store behind. A
`users.db` it made is never removed again, since a server starting at that moment may already
use it.

The command only uses key versions the server has recorded in the store, which it does when it
starts: a version added to the key file is used once the server was restarted with it. Until
then the command uses the newest version the server has, and says that the new one is not in use
yet, so the running server can always read what the command writes. (In a new store, before the
server ever started with a key, the command records its keys itself.)

    node scripts/users.js [--data-dir DIR] [--config FILE] COMMAND
      list                                  # role and two-step sign-in: app code, passkeys
      create NAME --role ROLE [--generate] [--must-change]
      set-role NAME ROLE [--force]
      reset-password NAME [--generate] [--must-change]
      reset-2fa NAME                        # app code, passkeys, recovery codes, known devices
      delete NAME [--force]
      backup FILE
      check
      rekey
      retire-users-json [--delete]
      gen-key [--version N]

`--data-dir` defaults to `DATA_DIR` (else `./data`), `--config` to `CONFIG_FILE`. With the config
file its admins count for the last-admin rule, its names cannot be taken, and `reset-2fa` works
for its users; without it, a note says so. `--generate` makes a one-time password, printed once,
that must be changed at the next sign in (`--must-change` asks the same of a typed one). A
password is never taken as an argument. `--force` lets the last admin be deleted or demoted, for
recovery only. `backup`, `check`, `rekey`, `retire-users-json` and `gen-key` are described in
[The user store](User-Store#the-user-store).
`--server-stopped`, which older versions needed, is still accepted and ignored, with a note. An
unknown option or command is not repeated in the error, since a mistyped line may hold a
password.

**Recovery.**

- *Lost the only admin password, or the admin left:* `scripts/users.js reset-password NAME
  --generate` for a website admin, or `create NEWNAME --role admin`; or give a config user
  `role: admin` and restart the server.
- *An admin lost their phone or security key:* `scripts/users.js reset-2fa NAME` on the server
  (add `--config` for a user in the config file); the Users page does not reset an admin. It says what went, for example "their app code, 2 passkeys, recovery codes
  and known devices are gone". Recovery codes work too, if they still have them.
- *The user store key is lost:* see [Backups](User-Store#backups).
- *The key, or a copy of the data, may have been seen by someone else:* see [What the key does
  not protect](User-Store).

**Moving users out of the config file.** Users in the config file never get the pepper (see [The
user store](User-Store#the-user-store)); move them, admins first, to give it to them. Create each user in the store first
(on the Users page or with `scripts/users.js`), with a name that is not in the config file, or
with the same name in this order: remove them from `users:` in the config file, restart, then
create them in the store (on the page or with the command line). While a name is in both, the
config file wins: the server warns at start and the store user cannot sign in. Make sure an
admin is left (another one in the store, or the user you are moving) before you take an admin
out of the config file. A config user's two-step sign-in and devices are kept in the store apart
from the website users and are **not** moved: a store user made with the same name starts
without two-step sign-in and without known devices, and must set it up again on the Account
page. The old record stays, unused (the command line mentions it), and would be used again only
if the name went back into the config file; reset it there first (`reset-2fa` with `--config`)
if you want it gone.
