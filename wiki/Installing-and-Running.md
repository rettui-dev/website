How to start the website server on your own machine or in Docker. The settings it reads are in [Configuration](Configuration).

## Run locally

Needs Node.js 24.7 or later (the login uses its built-in Argon2id, and the user store its
built-in SQLite, `node:sqlite`).

    npm start        # http://localhost:8080
    npm test
    npm run hash-password -- --name alice   # a password_hash for the config file (see "Logins")
    npm run users -- list                   # the users in the user store (see "Managing users")
    npm run users -- gen-key                # a user store key (see "The user store key")

The comments name these pages: [Logins](Logins#logins), [Managing users](Managing-Users#managing-users)
and [The user store key](User-Store#the-user-store-key).

## Docker

    docker compose up -d --build

This serves the site on port 8080. History and the user store are kept in the `status-data`
volume, so they survive restarts. The container runs as an unprivileged user (`node`, uid 1000)
with a read-only root file system; only `/data` and the `/tmp` in memory are writable. Keep
`/data` on a named local volume: the user store is a SQLite database, which must not be on NFS,
SMB or a volume shared between hosts (see [The user store](User-Store#the-user-store)). With users, the server also needs
the user store key, as a Docker secret (see [The user store key](User-Store#the-user-store-key)).

Without compose:

    docker build -t rettui-website .
    docker run -d -p 8080:8080 -v status-data:/data --read-only --tmpfs /tmp rettui-website
