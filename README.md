# rettui website

The website for [rettui](https://github.com/rettui-dev/rettui): a home page and a
status page that checks the project's Reticulum entry points. It has the same look
as rettui's web UI (colours, Fira Code Nerd Font, dark and light themes).

It is plain HTML, CSS and JavaScript, served by a small Node.js server
(`server.js`) with no dependencies and no build step. The server also probes the
hosts, keeps their history and can fetch their node stats.

## Pages

- `/` is the home page.
- `/status` shows, for each host, whether it is up, the connect time, when it was last
  checked, its uptime and a bar of the last 90 checks. It refreshes itself.
- `/api/status` is the same data as JSON.
- `/healthz` answers `ok` (used by the Docker health check).

## Run locally

Needs Node.js 22 or later.

    npm start        # http://localhost:8080
    npm test

## Docker

    docker compose up -d --build

This serves the site on port 8080. History is kept in the `status-data` volume, so it
survives restarts. The container runs as an unprivileged user with a read-only root
file system; only `/data` is writable.

Without compose:

    docker build -t rettui-website .
    docker run -d -p 8080:8080 -v status-data:/data --read-only rettui-website

## Settings

All optional, set in the environment (or `environment:` in `compose.yaml`).

| Variable         | Default                           | Meaning                                                  |
| ---------------- | --------------------------------- | -------------------------------------------------------- |
| `PORT`           | `8080`                            | Port to listen on.                                       |
| `HOST`           | `0.0.0.0`                         | Address to listen on.                                    |
| `DATA_DIR`       | `./data` (`/data` in Docker)      | Where `history.json` is kept.                            |
| `STATUS_TARGETS` | the four hosts in `lib/monitor.js` | Comma separated `host:port` list to monitor.             |
| `STATS_URLS`     | none                              | Comma separated `host:port=url` pairs: where to fetch each monitored host's node stats (see below). |

A bad value (for example a `STATUS_TARGETS` entry that is not `host:port`, or a `STATS_URLS` entry that is not an `http` or `https` URL for a monitored host) stops the
server at start with a message.

## Add a monitored host

Either set `STATUS_TARGETS`, for example
`STATUS_TARGETS=rns.rettui.dev:4242,other.example:4242`, or edit `DEFAULT_TARGETS` in
`lib/monitor.js`. Restart the server. A host removed from the list loses its saved history.

## How checking works

Every 30 seconds the server opens a TCP connection to each host (5 second timeout) and
closes it again. Up means the connection was made; the connect time is shown. The
hosts come only from the configuration; nothing a visitor sends is ever probed.
Up to 2880 checks per host (24 hours) are kept, and uptime is calculated over those.

## Node stats

A rettui node can publish a small `stats.json` (opt-in on the node). With `STATS_URLS`
set, the status page shows a second line under each such host: clients, interfaces
online, traffic, peers heard, announces per minute and node uptime. A host without a
stats URL shows nothing extra; a host whose stats cannot be fetched shows "Stats
unavailable". The production values are:

    STATS_URLS=rns.rettui.dev:4242=https://rns.rettui.dev/stats.json,front.rns.rettui.dev:4242=https://front.rns.rettui.dev/stats.json,back.rns.rettui.dev:4242=https://back.rns.rettui.dev/stats.json,side.rns.rettui.dev:4242=https://side.rns.rettui.dev/stats.json

On the same 30 second cycle as the probes, the server fetches each URL (5 second
timeout, at most 64 KiB, redirects are not followed). Each failure is independent and
never affects the up or down check. The answer is checked and rebuilt in a fixed shape:
numbers are clamped to whole non-negative numbers, text and lists are cut to length and
unknown keys are dropped; anything that does not fit counts as unavailable. The last good
stats are kept in memory and marked stale after three missed cycles. They are not saved
to `history.json`. `/api/status` has a `stats` field on each host: `null` when no URL is
set, else `{ok, fetchedAt, stale, error?, data?}`.

Security: a node exposes only aggregate numbers (no peer or identity details), and the
website fetches only the URLs set by the operator in `STATS_URLS`, never anything a
visitor sends. What a node answers is treated as untrusted and is shown as text only.

The fonts are Fira Code Nerd Font under the SIL Open Font License (`public/fonts/OFL.txt`).
