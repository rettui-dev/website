## Accounts and second factor

Everyone who can sign in has an account page, `/account`: the name in the header links to it once
signed in. It shows the name, the role, the last sign in, where the account is signed in (the sessions in
this server's memory, without addresses) and its known devices, and has the password and the
second factor: an app code, passkeys, or both (see "Passkeys"). The recovery codes work with
either.

**Where users live.** Users come from two places:

- **The config file** (`users:`, see [Logins](Logins#logins)), as before. These users keep working exactly as
  they did. Their name, password and role are set in the config file only; the account page
  says "Managed by config" and has no password change. Each may have a `role`: `admin`,
  `manage` or `viewer` (the default when it is left out).
- **The user store**, `users.db` in `DATA_DIR`, for users made on the website's Users page or
  with `scripts/users.js` (see [Managing users](Managing-Users#managing-users)). Each has a name, a role, an Argon2id password
  hash like those in the config file (peppered, see [The user store](User-Store#the-user-store)), the times it was made and
  last signed in, its second factor, and `mustChangePassword` while the password is one an admin
  set.

When a name is in both, the one in the config file is used and the server logs a warning at
start; the one in the store cannot sign in, and is left as it is. A user in the config file can
still turn on a second factor: it is kept in the store under the user's name, apart from the
website users, with nothing else. Roles are shown on the account page. `admin` opens the Users
page (see [Managing users](Managing-Users#managing-users)); nothing else depends on the role yet.

**The store.** `users.db` is a SQLite database (see [The user store](User-Store#the-user-store) for the key, backups and
the volume it needs). Every change is one short transaction, written to disk before it is
answered, so a crash never leaves half a change. A store that cannot be read (damaged, made by a
newer version, a record that makes no sense, a table, column, trigger or view this version does
not make, or a key that does not fit) stops the server at start with a message that says why,
and the file is left as it is: a broken store never becomes an empty one, which would drop
everyone's second factor. Fix or move the file (or give the right key) and start again. The file
is made with mode 0600, and a store that other users can read gets a warning at start. A link in
place of `users.db`, `users.db-wal` or `users.db-shm`, or anything else that is not a plain file,
is refused before the store is opened. Deleted rows are overwritten in the file (SQLite's
`secure_delete`), not left in its free space. SQLite keeps the latest changes in `users.db-wal`
for a while, old pages included; so after a user is deleted, or a password, TOTP secret or
recovery code is replaced or used, the server also empties `users.db-wal` into `users.db` (a
checkpoint, at most once a second, and tried again later when another program is reading the
store just then). The sqlite_stat tables that SQLite's `ANALYZE` makes are allowed; anything else
this version does not make is not.

The store holds at most 500 website users (and as many records for users in the config file),
20 recovery codes and 10 known devices per user. A change past that is refused (the Users page
says "The user store is full", with 409 for the user count and 500 otherwise) and nothing
changes.

**Changes from the command line.** `scripts/users.js` may change the store while the server runs
(see [Managing users](Managing-Users#managing-users)); there is no lock file and nothing to stop first. The server looks for
such changes once a second and before each of its own writes, reads the store again, and signs
out every user who was made, deleted, or given another password, role or second factor there
(an audit line, `user-changed-elsewhere`, says who and what). A change of its own that runs
into one of those is given up, the users concerned are signed out first, and it is tried again,
so a request from a session that was just ended is refused. Each write holds the store for
milliseconds; a server that finds it held for more than a second answers that change with 500
"Another program is changing the user store; nothing was changed. Try again."

**When the store cannot be read again.** If what the server finds there cannot be read (a row it
cannot decrypt with the keys it has, a damaged row, a trigger or table put in by something
else), what it has in memory may be out of date: a user deleted there could still sign in. So
the server then turns signing in off (`/login` answers 503 "Signing in is not possible right
now. Try again later."), ends every session, logs an error line and writes
`user-store-unreadable` to the audit log. It tries again every second; once the store can be
read, signing in is back on by itself (`user-store-readable`). Fix what the error line says, or
restart the server with the right keys.

TOTP secrets are kept encrypted with the user store key, and recovery codes only as a keyed hash
(see [The user store](User-Store#the-user-store)), so the database alone gives neither. Keep the data directory as private
as the config file anyway, and back it up (see [Backups](User-Store#backups)). A passkey's record (its public key,
name and counter) is in the store too; a public key cannot sign in.

**Two-step sign-in with an app code (TOTP).** On the account page, Set up two-step sign-in shows a QR code and the
same key as text, for any authenticator app (RFC 6238: HMAC-SHA1, 6 digits, 30 seconds). The key
is a new random 20-byte secret, and it is shown this once, to its owner: no later answer contains
it, it is never in a URL and never logged. It is only turned on once the first code from the app
is right; turning it on gives ten recovery codes, shown once too, with Copy and Download buttons
(they replace any recovery codes the user already had from a passkey). Each recovery code signs in
once instead of any other second step: the code from the app or a passkey. New recovery codes
replace all the old ones. The recovery codes belong to the second step as a whole: they are made
when the first way (app code or passkey) is turned on, and they are removed only when the last way
is turned off. Setting it up needs the password; new recovery codes and turning it off need the
password and a second step (a passkey, a code from the app or a recovery code) (see "Changes need
a recent sign in").

With a second step on, a right password no longer signs in by itself. `/login` answers 200 with
`{"ok": false, "secondFactor": true, "pending": "..."}` (and `methods`, the ways the user can answer, and
`passkey`, the options for the browser, when a passkey can be used here) and no cookie, and the sign in dialog asks
for the passkey, the code or, with "Use a recovery code", a recovery code. The code and the recovery code are posted to `/login/code`
with the `pending` token (a form, like `/login`); the passkey to `/login/passkey` (see "Passkeys"). The token is good for 5 minutes, for one sign in,
only from the address that gave the password, and for 5 wrong codes; then the dialog goes back to
the password. A wrong password gets the same answer as before, so nothing says whether a name has
a second factor before the password is right.

- A code is taken from the 30 seconds before, now and the 30 seconds after, so a phone clock that
  is a little off still works. Each code works once: a code (or an older one) that was used
  already is refused, also after a restart.
- Wrong codes count per user and address (per user and device for a known device), and per user
  from everywhere together. For a user and address, the first five are free; after that each one
  doubles the wait, up to an hour (answer 429 with `Retry-After` and the wait in words). For the
  user in all, 30 are free, then the same doubling wait, for every browser that is not a known
  device; a known device is only held back by it once the user has 200 wrong codes. They are
  remembered for a day after the last one, so the free tries do not come back after a short
  pause: someone who knows the password gets at most 40 guesses at the code from one address on
  the first day and 24 a day after that, and at most 65 on the first day from all their
  addresses together (then 24 a day). Someone with the password can so hold back the code step
  of the owner's new browsers, but not of a known device. A right password does not start the
  count again: it is only cleared by a right code. Wrong codes also count for the address in the
  same count as wrong passwords.
- This wait only holds back the code step, never the password step. A right password while it
  runs says so: with a wait shorter than the 5 minutes of a second step, `/login` gives the token
  with `codeWait` (seconds) and `notice`, which the dialog shows; with a longer one it answers 429
  "Too many wrong codes were entered for this account. Sign in again in N minutes." and no token.
  A code sent during the wait is answered 429 with the time; if the wait outlasts the token, the
  answer has `restart: true` and the dialog goes back to the password.
- A password change, turning the second factor off, and the other changes below end every second
  step of the user that is still open, also one started with the old password.

**Changes need a recent sign in.** Changing the password, setting up, turning on or off the second
factor, making new recovery codes and signing out other sessions need a sign in from the last 15
minutes. After that the page asks for the password again (`POST /api/account/reauth`) and then goes
on. That can be done at most 10 times an hour from one session and 20 times an hour for one user
(20 times a day for the user in sessions made with a passkey alone),
right and wrong passwords alike (a right one does not start the count again); past that the
answer is 429 with `Retry-After`. Some need more in the request itself, and the page asks for it
in a pop-up (the step-up dialog) when the button is pressed, not in boxes on the page:

- **Password change, new recovery codes, turning the app code off, adding and removing a
  passkey** (and every change on the Users page): the password (`password`) **and**, when a second
  step is on, a passkey (`passkey`), a current code from the app (`code`) or an unused recovery
  code (`recovery`). Neither is enough alone: the password alone is refused with 400 and
  `field: "code"`, a code alone with `field: "password"`. A wrong passkey is refused with 400 and
  `field: "passkey"`. A passkey is asked for with a challenge from `POST
  /api/account/passkeys/challenge` (409 when the user has no passkey that works at this address;
  30 a session and 60 a user an hour), and each challenge works once.
  A missing code is refused before the password is checked (no hash, no try counted); the code
  is only checked once the password is right, so a wrong password never uses up a code. A code
  counts like one at sign in: a wrong one counts in the same waits, and a code (and its 30
  seconds) works once, so a request cannot be replayed. A recovery code used here is used up and
  is an audit line, as at sign in. Users without two-step sign-in give the password only. The
  dialog has "Your password", and with two-step sign-in on asks for the passkey first (when the
  user has one that works at this address and the browser can use it), or "Code from your app", with
  "Use the code from your app instead" and "Use a recovery code instead" as the other ways; it keeps the keyboard focus inside, closes with Escape, gives the
  focus back to the button, and shows a wrong password or code inside it. When the sign in is
  older than 15 minutes, the password given there makes it recent again first.
- **Password change:** the current password is the step-up's password (`password`; `current`,
  the older name, is still read). It is for website users only. The new one needs at
  least 12 characters and at most 1024 bytes, must not be one of a built-in list of the most
  common passwords (any case), one character over and over, or the name with fewer than 8 other
  characters. Passwords in the config file are not checked: the server only has their hash, so
  pick them with the same care.
- **Set up the app code:** the password (`password`), in the same dialog, and a second step too
  when one is on already (a passkey, say); then the first code from the app, on the page, turns it
  on.

A password asked for while signed in counts in a wait of that session (five free, then doubling),
kept apart from every other count, so nobody outside can hold a signed-in user back by sending
wrong passwords for the name, nor push that wait out by filling the other counts.

A session can end while one of its changes is under way: a password change or sign out elsewhere,
or the user removed. Each change checks after every step that its session is still there, and
the store checks it again right before writing. If it is gone, the answer is 401, nothing is
changed, and no secret (a new key or recovery codes) is handed out. A password check that was
under way when the password changed does not sign in.

Changing the password, turning the app code on or off, adding a user's first passkey and removing
any passkey sign the account out everywhere else (adding a second passkey does not; the session
that made the change stays), drop any second step still open, and forget every
known device but the one that made the change. **Sign out other sessions**, under "Where you are
signed in" (`POST /api/account/sign-out-others`), does the same on its own.

**Known devices.** Under "Known devices" the page lists the browsers the account signed in from
(see [How the login works](Logins)). A device has no name the server knows, so each shows when it was
first and last used, and "this browser" for the current one. **Remove** forgets one (`POST
/api/account/devices/remove` with its `device` id from `GET /api/account`), and **Remove all
other devices** forgets every one but this browser (`POST /api/account/devices/remove-others`).
Removing a device also signs it out: every session that was signed in on it ends (the answer
says how many, `ended`), and removing this browser's own device signs this browser out. A
removed device is held back like any other browser until it signs in again. Removing takes effect
at once, also when writing the user store fails.

Setting up, turning on and off, new recovery codes, signing out other sessions and adding or
removing a passkey (the three steps `passkeys/begin`, `passkeys/finish` and `passkeys/remove`) can
each be done at most 5 times an hour from one session and 10 times an hour for one user, wrong
passwords and codes included; past that the answer is 429 with `Retry-After`. Renaming a passkey is
not counted.

A change is written to the user store first and only then made: when the write fails (a full
disk, a full user store, or the store held by `scripts/users.js` for longer than a second, see
"Changes from the command line"), the answer is 500 and says which ("Another program is changing
the user store; nothing was changed. Try again." for the last), nothing has changed, and nobody
was signed out.

**LXMF alerts.** When the site has an LXMF bridge that takes addresses the website names (a webhook
channel with `user_addresses: true`, see [Uptime and alerts](Uptime-and-Alerts#alerts)), the account page
has an "LXMF alerts" card. Without it the card is not there. Enter an LXMF address (32 hex digits;
angle brackets, spaces around it and capitals are fine, and it is kept in lower case) and the
website sends a 6-digit code to it. Type the code back to confirm the address: until then
nothing else is sent there. The code works for 15 minutes and ends after 5 wrong tries; ask for a
new one with "Send a new code" (3 codes an hour for you, a small number for the whole site). A message
can take a while to arrive over LXMF. If the bridge refuses, the page says why in plain words: the
bridge has website addresses turned off, it has sent the most it allows to that address (and for how
long to wait), or it is busy.

Once it is confirmed, the address gets a message when something changes about your account: a
passkey is added or removed, your password is changed (by you, or reset by an admin, who is named), your app code is turned off or your two-step
sign-in is reset by an admin, or new recovery codes are made. Each says what happened and when, never a
passkey id, a secret or an address. Admins and managers can also tick "Node down and recovered
alerts" to get the node alerts the site's operator gets. Changing the address tells the old one; removing it
too. Setting, changing and removing the address, asking for a code and the tick need your password
from the last 15 minutes (a pop-up asks when it is older), like the other changes here; a session made with
a passkey alone gives the password first, and does not show the address until then. The address stays
when you change your password or remove a passkey, so that the alert about it still reaches you, and
goes with the user when they are deleted. A bridge that is down never stops a change from being made.
The details are in [Uptime and alerts](Uptime-and-Alerts#alerts).

**The account API.** `GET /api/account` says who is signed in, and never holds a secret. The
changes are `POST /api/account/reauth`, `/password`, `/totp/setup`, `/totp/enable`,
`/totp/disable`, `/recovery-codes`, `/sign-out-others`, `/devices/remove`,
`/devices/remove-others`, `/passkeys/challenge`, `/passkeys/begin`, `/passkeys/finish`,
`/passkeys/rename` and `/passkeys/remove`, and, only with an LXMF bridge for users' addresses,
`/lxmf/set` (`{address}`: sends a code, keeps the address once the bridge took it),
`/lxmf/resend`, `/lxmf/confirm` (`{code}`), `/lxmf/remove` and `/lxmf/node-alerts` (`{enabled}`).
`GET /api/account` has an `lxmf` object (`available`, and with it `set`, `address`, `confirmed`,
`canNodeAlerts`, `nodeAlerts`, `codeExpiresAt`; `address` is null with `hidden: true` in a session made
with a passkey alone that has not given the password). `GET /api/account` also says whether passkeys are
available here (`passkeys.available`, with `reason: "no-address"` when `site.url` is not set), and
lists them (`passkeys.signIn` says whether signing in with a passkey alone is on; `passkeys.list`: `id`, `name`, `created`, `lastUsed`, `synced`, and `here`, false for a
passkey made for another address). Ids are short references, never the credential id or key. They
only take JSON (`Content-Type: application/json`, at most 16 KiB, as a new passkey's answer is
several kilobytes), with the header `X-Rettui-Request: 1`, from the page itself (`Sec-Fetch-Site:
same-origin`, or `Origin` naming the host, and nothing else: an `Origin` with a user name or a
path is refused); a form on another site can send none of these.
Without a session the answer is 401. All answers carry `Cache-Control: no-store`.

**Audit log.** `audit.log` in `DATA_DIR` gets one JSON line per security event, appended, mode
0600: `password-changed` (`with`), `totp-enabled`, `totp-disabled` (`with`: `password`,
`password+code` or `password+recovery`),
`recovery-code-used` (with how many are `left`), `recovery-codes-regenerated` (`with`),
`second-factor-orphaned` (the record of a config user who is gone from the config file was removed
at start, `user` only, see [Managing users](Managing-Users#managing-users)),
`sessions-ended` (how many were `ended`), `device-added` (a sign in from a new browser),
`device-removed` and `devices-removed` (how many were `removed`, and how many sessions that
ended, `ended`). Turning on a first second factor (the app code, or a first passkey, with no
other second factor on) adds `second-factor-first` as well (`role`, `method`: `totp` or
`passkey`, and `nodeChangesFrom`: when the wait before node changes ends, see [Managing nodes](Managing-Nodes#managing-nodes)).
The LXMF address adds `lxmf-address-set`, `lxmf-code-sent`, `lxmf-address-confirmed`, `lxmf-address-removed`
and `lxmf-node-alerts` (`enabled`), each with the `user` and `lxmf`: the first 8 digits of the address, never the
whole one or a code. Passkeys add `passkey-added` (`passkey`: its name, `first`: whether it is the
user's first second step), `passkey-renamed` (`from`, `to`), `passkey-removed` (`passkey`, `with`,
`ended`, `secondFactorOff`) and `passkey-counter-error` (`passkey`: a passkey answered right but
its counter did not go up, see "Passkeys"; `step: "sign-in"` when it was a sign in with the passkey alone). `device-added` has `with: "passkey"` for a sign in with a passkey alone. A passkey is named by its name only: no credential id
or key is ever in a line. Changes on the Users page add `user-created` (`role`, and `password`:
`generated` or `typed`), `user-role-changed` (`from`, `to`), `user-deleted` (`role`),
`user-password-reset` (`password`, and `passkeys`: how many passkeys the reset removed, only when
the admin asked for that) and `user-second-factor-reset` (with `passkeys`: how many
passkeys it removed); each of those has the admin
who made it (`actor`), the `user` it was made to, how many of their sessions `ended`, and how
the admin confirmed it (`with`). A change made with `scripts/users.js` is
`user-changed-elsewhere` (`what`: `created`, `deleted`, `password`, `role` or `second-factor`),
written by the server when it notices it. The server also writes `user-store-imported` when it
imports `users.json` (with `again: true` when a user store had been made in the data directory
before, see [From users.json](User-Store#from-usersjson)), `key-added` for each user store key version it sees for the
first time, and `user-store-unreadable` (`sessionsEnded`) and `user-store-readable` when the
store cannot be read again and when it can (see "When the store cannot be read again").
`user-role-changed` has the role the user had right before the
change, also when another change came in between. A try on the Users page to reset the password
or the two-step sign-in of an **admin** is refused and written as `admin-reset-refused`, with the
`actor`, the `target` admin and `what` they tried to reset (`password` or `second-factor`); a try
to give another admin a lower role is refused and written as `admin-demote-refused`, and a try to
delete another admin as `admin-delete-refused`, both with the `actor` and the `target` admin; see
[Managing users](Managing-Users#managing-users). Each line has the time, the user and the address. No password, secret, code or
device id is ever in it. Changes asked of a node on the Manage page add `manage-settings`,
`manage-restart`, `manage-rollback` and `manage-reticulum`, and the website's confirm of a Reticulum
change adds `manage-confirm` (see [Managing nodes](Managing-Nodes#managing-nodes)). `device-added` is only written for a user's first new browser in 24
hours, or when the new browser pushes out a known device older than that (`pushedOut`: how
many); the other new browsers are summed up in `failures.log`, so that an account signing in from
new browsers over and over cannot push the other events out of `audit.log`.

Wrong passwords and codes go to `failures.log` instead, so that no amount of them can push a
security event out of `audit.log`. They are summed up: one line per name and kind
(`password-failures`, `second-factor-failures`, `reauth-failures` for wrong passwords asked again in
a session made with a passkey alone, `passkey-sign-in`, `passkey-sign-in-paced` and `device-added`
for the new browsers above, counted in `failures`) per 15 minutes, with how many `failures`, from
how many `addresses` (`100+` past a hundred), the `lastAddress`, and when the first and last were
(`from`, `to`). Every name gets its lines, known or not. A summary is written once its 15 minutes
are over, and all of them when the server stops. At most 10000 are summed up at once; past that
the oldest is written early.

Both are bounded: a line that would take one past 5 MiB first moves it to `.1` (and `.1` to `.2`);
three files of each are kept, the oldest is dropped. So copy `audit.log` off the server as it
grows (a log shipper, or a timer that copies it to another machine): a long enough run of events
still pushes old lines out, and whoever takes over the server can change the copy that stays on it.

## Passkeys

A passkey is the user's phone, computer or security key confirming it is them, with a fingerprint,
face or PIN, and there is nothing to type. It works as the second step after the password, next to
the app code (TOTP), and it can also sign in on its own (see "Signing in with a passkey alone").
Users can have an app code, passkeys, or both.

**What you need.** Users (see [Logins](Logins#logins)) and the site's public address:

- Set `site.url` in the config file, or `SITE_URL` without one, to the https address people use,
  like `https://status.example.org` (no path). For trying it out on your own machine,
  `http://localhost` (with or without a port) works too.
- Without it the Account page says "Passkeys need this site's https address in the config file
  (site.url, or SITE_URL)." and the server prints `passkeys: off` at start when it has users,
  with the reason (no address set, or one passkeys cannot use). The password and the app code are
  not affected.
- The address must have a host name. An IP address cannot be used for passkeys: `site.url` takes
  one (for the feed and the page previews), but passkeys stay off, and the start says "the site
  address (site.url, or SITE_URL) is an IP address; passkeys need a host name".
- **A passkey is tied to the host name** in that address (`status.example.org` above), and only
  works at the exact address it was made for. **Changing `site.url` later stops the passkeys made
  before working**: they stay in the list, marked "Not usable at this address.", and can still be
  removed. Users with an app code or recovery codes sign in with those, and an admin can reset the
  rest (see [Managing users](Managing-Users#managing-users)). Decide the address before people add passkeys.

In Docker, put it in `compose.yaml` and restart:

    environment:
      SITE_URL: "https://status.example.org"

(or `site.url` in the config file, if you use `CONFIG_FILE`). Behind a reverse proxy this is the
address the proxy serves, not `http://website:8080`.

**Adding one.** On the Account page, "Passkeys", give it a name if you like (up to 64 characters,
such as "Work laptop", without control, bidirectional or zero-width characters or more than three
accents in a row on one letter; the default is "Passkey 1", "Passkey 2" and so on) and press "Add a
passkey". A pop-up asks for the password, and for a second step when the user has one already.
Then the device asks the user to make the passkey. A user can have 10. The list shows each
passkey's name, when it was added and last used, and whether it is synced or device-bound. Each can
be renamed or removed. A name in the user store that these rules refuse (one changed by hand, say)
is shown as "Passkey N", by its place in the list, and the passkey keeps working.

- The first second step of a user (the first passkey, or the app code) gives ten recovery codes,
  shown once, and signs every other session out. A second passkey changes neither.
- Removing a passkey asks for the password and a second step, and signs every other session out.
- **An alert when a passkey is added.** Someone who got hold of a password and a code can add a
  passkey of their own, and it then signs in without either. The operator can ask to be told: list
  `passkey_added` in `alerts.events` (it is not in the default list, so nothing changes without it;
  see [Alerts](Uptime-and-Alerts#alerts)). Each passkey added by anyone sends a message to the
  configured channels, for example `bob (manage) added a passkey named "Work laptop" at 2026-11-19
  12:03 UTC.` It names the user, their role, the passkey's name and the time, and nothing else: no
  credential id, no address, no secret. The name is typed by the user, so it is shown in quotes as a
  JSON string (a `"` in it is escaped), and for Discord its Markdown is escaped as well. A user's
  alerts are held to one in each `cooldown_minutes` (default 15); the passkeys added in between are
  counted, and an alert goes out when the cooldown ends (or with the next add, if that comes first)
  and says "2 more passkeys were added by this user since the last alert, and not announced". A channel that is
  down, slow or refusing never fails or delays adding the passkey. The `passkey-added` line in
  `audit.log` is written either way.
- The Account page says when the browser cannot make passkeys. Users can still rename and remove
  the ones they have.

**Signing in.** The password comes first, as always. Then the dialog offers, in this order:

1. **Use your passkey**, a button. Pressing it makes the browser ask for the passkey. It does not
   start by itself, because some browsers (Safari) only show the prompt after a tap or click.
2. **Use the code from the app**, when the app code is on.
3. **Use a recovery code**, while any are left.

Only passkeys made at the site's current address are offered. A user who has passkeys but none that
work here still gets the second step, with the app code or a recovery code, and a note that the
passkey does not work at this address. A passkey that fails counts exactly as a wrong code: the
same waits and limits, and it is summed up in `failures.log` as
`second-factor-failures` (see "Two-step sign-in with an app code (TOTP)"). The same choice is made
when a change on the Account page or the Users page asks for a second step (the dialog asks for the
passkey first).

### Signing in with a passkey alone

The sign in dialog has a second button under the form, "Sign
in with a passkey". It needs no name and no password: the browser lists the passkeys it has for this
site, the user picks one and confirms with their fingerprint, face or PIN, and that is the whole
sign in. It counts as a complete two-step sign in (the passkey is what you have, the fingerprint or
PIN is what you are or know), so there is no second prompt, and it passes the rule that managing
nodes needs two-step sign-in. It is on wherever passkeys work; set `login.passkey_sign_in: false`
(or `LOGIN_PASSKEY_SIGN_IN=false`) to turn it off (see [Configuration](Configuration)). It is
offered on the site's own address only (`site.url`).

- **Which passkeys work.** The server needs the passkey to be discoverable, so that the browser can
  list it without a name. Passkeys made by phones, computers and password managers (iCloud, Google,
  Windows Hello, 1Password, Bitwarden) are, and work at once. Some security keys, and every key
  that only speaks the older U2F, are not: the browser shows no passkey for them. The sign in says
  "No passkey was used. If yours did not show up, sign in with your name and password, then add a
  passkey on your account page." Adding the passkey again makes a discoverable one; the old one can
  stay as a second step. Nothing is stored about which passkeys are discoverable, and the user
  store does not change.
- **What is checked.** The server finds the account from the passkey's id and the user handle the
  passkey sends (a random value kept for the user, never their name), and checks that the user
  verified themselves, the signature, the address, and the counter, as for the second step.
  The passkey must send the user's own handle. A passkey that does not (an old record) still
  works as a second step.
- **Adding the same security key again.** A browser does not make a second passkey on a security
  key that already holds one for this site: it refuses. To make a discoverable passkey on such a
  key, remove the old passkey first (the key then holds one that works on its own), or use another
  key. The site asks the browser to prefer a discoverable passkey; that is a preference, and some
  keys still make one that cannot sign in alone.
- **Changes still need the password.** A session made with a passkey alone has not given the
  password, so it is not "recently signed in": every change on the Account page, the Users page and
  the Manage page (changing the password, setting up or turning off the app code, new recovery codes,
  adding, renaming or removing a passkey, signing out other sessions, forgetting devices) first asks
  for the password, and then, for the changes that already asked for one, for a second step as
  before. The password is good for 15 minutes in that session, as after a password sign in. The page
  asks by itself ("Enter your password again to do this"). A sign in with the password and a passkey
  as the second step has just given the password, so it is not asked at once. A passkey session has
  its own count of password tries per user, 20 a day (the owner's password sessions have 20 an
  hour, apart), so someone who holds a stolen passkey cannot use up the tries of the owner's own
  sessions. A wrong password given again in such a session is counted in `failures.log` as
  `reauth-failures` for the user (the password sessions' own slips are not). Once the 20 are used,
  the answer is 429 with a wait of up to a day; the owner can still sign in with the password, which
  gives sessions with their own tries. The wait before node changes after a user's first second factor
  (see [Managing nodes](Managing-Nodes#managing-nodes)) is not shortened or started by it.
- **Reads that need the password too.** A passkey someone else added would otherwise let them look
  at what only managers and admins see. So a session made with a passkey alone has to give its
  password once before it may read the **Manage** page's data (the nodes, a node's state, its list of
  changes, the state of a Reticulum change), the **Users** list, or a node's **logs** (where they are
  not public). Until then each of those answers 403 with `reauth: true`, the same answer the changes
  get, and the page opens its password pop-up and loads once it is given. The pages themselves are
  still served, since they hold nothing and have to be there to ask. Unlike a change, this is not a
  15 minute window: once the password is given in this session, reads stay open for the life of that
  session (changes still ask again after 15 minutes). The **status page** is held back the same way
  for the sections that need a login: until the password is given, `/api/status` and `/api/stats` show
  such a session the public view, as if signed out (`locked` lists what the password would open), and
  `/api/status` adds `passwordNeeded: true` to `viewer`. The page then says "You signed in with a
  passkey. Some details need your password too." with a button, **Enter your password to see
  everything**, which opens the password pop-up and loads the numbers again once; it never opens by
  itself and is not asked on every refresh. The Account page stays open to such a session, and a
  session made with the password, or with the password and a passkey as the second step, is never asked. The website's own
  reads of the nodes (the links it detects, the check of a Reticulum change) have no session and are
  not affected.
- **Known devices.** A browser signed in with a passkey alone is remembered as a device for passkey
  sign ins only. A password typed there is treated as from a new device (it gets the waits of the
  address and the name), and a password sign in on that browser makes a device of its own. Wrong
  passwords from all of a user's known devices together are also held back after 200 of them. A
  user has at most 3 such devices, and a new one pushes out only the oldest of them, never a device
  made with the password (when the list of 10 holds only those, the new browser is simply not
  remembered). Their ids start with `pk`; the ids of the others never do. The server keeps no other
  record of which is which, so that `users.db` stays as older versions read it; after a restart the
  devices of an earlier run count as the others when the list is full.
- **Limits against someone who holds a passkey.** A user has at most 5 sessions made with a passkey
  alone; a new one ends the oldest of those and never a session made with the password, however
  often it is used. Sign ins that work are paced for each user: three at once, then one a minute
  (429 with a wait, "Too many passkey sign ins for this user right now"; the password is not
  held back and neither are other users). A passkey that does not work on a browser the user has
  made known counts in a wait of its own for passkeys, and a passkey that works clears only that
  one: it gives the browser no fresh tries at the password.
- **Any role may use it**, admins and managers too.
- **Failures** are one and the same answer ("That passkey did not work. Try again, or sign in with
  your name and password."), count for the address and not for the user, and are summed up in
  `failures.log` as `passkey-sign-in-failures` (with the address, never a name or a passkey). A
  sign in by a manager or an admin is an `audit.log` line, `passkey-sign-in` (the user, the role, the
  passkey's name and the address, never its id or the user handle), but at most one a day for each
  user and passkey, and also one with a new browser that has its own `device-added` line; the others
  are only counted in `failures.log` as `passkey-sign-in`, and so are all of those of viewers. So
  nobody who signs in over and over can push the older lines out of `audit.log`. Sign ins refused
  because a user signed in too often are counted as `passkey-sign-in-paced`. A new browser's
  `device-added` line says `with: "passkey"`. A counter that went back is the usual `passkey-counter-error`, with `step:
  "sign-in"`. See [Logins](Logins#logins) for the routes, the limits and the waits.

> **Warning: a passkey keeps signing in after a password change.** Changing or resetting the
> password does not remove a passkey on its own, so a passkey that someone else added (with the
> password and a phished code, say) still signs in afterwards. That is why **Also remove my other
> passkeys** is ticked when you change your own password (see below), and **Also remove this user's
> passkeys** is ticked when an admin resets a password (see [Managing users](Managing-Users#managing-users)).
> `scripts/users.js reset-password NAME --remove-passkeys` does the same on the server. Unticked, or
> from a script that does not ask for it, the passkeys stay. **Reset two-step** (the Users page, or
> `scripts/users.js reset-2fa`) removes every passkey, the app code and the recovery codes.

**Also remove my other passkeys.** The form that changes the password has a tick box with this
name, shown only while you have passkeys and **ticked by default**: a passkey that someone else
planted would keep signing in after the change, so the safe choice is the one you get. Untick it to
keep your other passkeys; the help under it says so. While it is ticked the page always asks for the
removal, even if the box is hidden (a passkey added after the page was loaded goes too). The change is confirmed as always (the current password and a second step).
When it is confirmed with a passkey, every passkey except that one is removed; when it is confirmed
with a code from the app or a recovery code, all passkeys are removed. You can add them again
afterwards. It is one write with the password change: both change or, if the write fails, neither (the answer
is 500 and says nothing was changed), and other sessions are signed out as
for any password change, the page says how many passkeys were removed, and `audit.log` gets
`passkeys-removed-with-password` with the count (never a passkey id). Left unticked, nothing changes
but the password, and the page reminds you that passkeys still sign in. Nobody can ask for it
without the same confirmation: the request is refused like any password change without it. The
ticked box is only the page's default: the server removes passkeys only when the request says
`removeOtherPasskeys: true` (the boolean; `"true"`, `1` and a missing field do not), so an older page
or a script that sends nothing keeps them, as before.

**Synced and device-bound.** Some passkeys are copied by the user's password manager or phone
account to their other devices ("synced"); others stay on one device or security key
("device-bound"). The Account page says which, going by what the device reported to the server. A
device-bound passkey is gone if the device is lost or reset. Recovery codes cover both, so tell
users to keep them.

**The counter and the clone warning.** A device-bound passkey counts its uses. When a sign in
answers with a signature that is right, but a counter that did not go up, the sign in is refused
and `passkey-counter-error` is written to `audit.log` (with the passkey's name). It can mean the
passkey was copied. Synced passkeys always send 0, which is accepted. The sign in dialog says that
passkey did not work and offers the other ways.

**When the last second step is removed.** Removing the user's last passkey (with no app code on),
or turning off the app code with no passkey left, turns two-step sign-in off: the recovery codes
are removed and the password alone signs in. The dialog says so before it goes ahead. While one
way is left, the recovery codes stay.

**Admin reset.** Reset two-step sign-in on the Users page (or `scripts/users.js reset-2fa NAME`,
the only way for an admin's) removes the app code, every passkey and the recovery codes, and forgets the known devices (see
[Managing users](Managing-Users#managing-users)). The audit line has how many `passkeys` it removed.

**Browsers.** A page can use passkeys only in a secure context: over https, or on `localhost`. Use
a current browser. Where the browser cannot use passkeys, the page says so, and the sign in
offers the app code and recovery codes.

**Going back to an older version.** An older version of this website knows nothing about passkeys.
So that it can never let a user whose only second step is a passkey sign in with the password
alone, the first passkey anyone adds raises the version of `users.db` (schema version 2), and the
version before passkeys then refuses to start with it ("made by a newer version"). A store where
nobody has added a passkey stays at version 1, and an older version reads it as before. To go back
after passkeys were used, remove every passkey (on the Account page, or with `reset-2fa` for each
user who has one, or the Reset two-step button on the Users page): when the last passkey anywhere
goes, the version goes back to 1 and the older version opens the store again. Give users who had
only a passkey the app code first, or tell them to set up two-step sign-in again afterwards: until
then their password alone signs them in.

**The library.** WebAuthn is checked by `@simplewebauthn/server`, the only package added for it.
Only `lib/passkeys.js` uses it, after it has checked the size and shape of everything the browser
sent.

- It is pinned to an exact version in `package.json` (no `^` or `~`), and `package-lock.json` is
  committed. The Docker image installs with `npm ci --omit=dev --ignore-scripts`, so no install
  script of it or of anything it brings runs. Run the same when you install outside Docker.
- Only attestation `none` is accepted (and `packed` signed by the new key itself, with no
  certificate). A passkey that comes with a certificate is refused: "This security key sent a
  certificate, which this site does not accept. Try another passkey." The library's certificate
  code never runs.
- There is no metadata service, and passkeys cause no request to any other server.
- To check that the downloaded packages are the ones the registry signed, after `npm ci`:

      npm audit signatures

The algorithms are ES256 (a P-256 key, a point on the curve), EdDSA (an Ed25519 key, not one of
the points of small order) and RS256 (an RSA key of at least 2048 bits, with the exponent 65537);
a key that is not what its algorithm says is refused when the passkey is added. The
device must verify the user (a PIN or biometrics). A passkey that another user has added already is
refused like one that could not be checked, so that nobody can find out which passkeys others
have; `failures.log` notes it as `passkey-id-taken`. The pages send
`Permissions-Policy: publickey-credentials-get=(self), publickey-credentials-create=(self)`, so a
page of another site cannot use passkeys for this one, even in a frame.
