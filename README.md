# rettui website

The website for [rettui](https://github.com/rettui-dev/rettui): a home page and a
status page that checks the project's Reticulum entry points. It has the same look
as rettui's web UI (colours, Fira Code Nerd Font, dark and light themes).

It is plain HTML, CSS and JavaScript, served by a small Node.js server
(`server.js`) with no dependencies and no build step. The server also probes the
hosts and keeps their history.

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

A bad value (for example a `STATUS_TARGETS` entry that is not `host:port`) stops the
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

The fonts are Fira Code Nerd Font under the SIL Open Font License (`public/fonts/OFL.txt`).
