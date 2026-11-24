# rettui website

The website for [rettui](https://github.com/rettui-dev/rettui): a home page and a
status page that checks the project's Reticulum entry points. It has the same look
as rettui's web UI (colours, Fira Sans and Fira Code, dark and light themes).

It is plain HTML, CSS and JavaScript, served by a small Node.js server
(`server.js`) with no build step and two dependencies (`yaml`, and `@simplewebauthn/server` for
passkeys, see [Accounts and Second Factor](wiki/Accounts-and-Second-Factor.md)). The server also probes the hosts, keeps their history and can fetch
their node stats.

## Run it

Needs Node.js 24.7 or later.

    npm start        # http://localhost:8080
    npm test

With Docker (port 8080; history and the user store are kept in the `status-data` volume):

    docker compose up -d --build

To list your own nodes, point `CONFIG_FILE` at a YAML file (start from
`config.example.yaml`). See [Installing and Running](wiki/Installing-and-Running.md) and
[Configuration](wiki/Configuration.md) for everything else.

## Documentation

The full documentation is in [`wiki/`](wiki/Home.md), and is published to the GitHub wiki.

Getting started

- [Installing and Running](wiki/Installing-and-Running.md): run locally or in Docker
- [Configuration](wiki/Configuration.md): environment variables, the config file, status-only mode, branding
- [Pages and Themes](wiki/Pages-and-Themes.md): every page and endpoint, Join, Downloads, release feed, accessibility

Running a status site

- [Node Stats](wiki/Node-Stats.md): what the website reads from nodes, groups, the network map
- [Uptime and Alerts](wiki/Uptime-and-Alerts.md): the 90 day record, incidents, webhook and email alerts
- [Public Data and Stats API](wiki/Public-Data-and-Stats-API.md): what visitors see, and the public JSON API

Logins and users

- [Logins](wiki/Logins.md): users in the config file, what is locked, sessions
- [Accounts and Second Factor](wiki/Accounts-and-Second-Factor.md): the account page, app codes, passkeys
- [Managing Users](wiki/Managing-Users.md): the Users page and `scripts/users.js`
- [User Store](wiki/User-Store.md): the user database, its key and backups

Nodes

- [Managing Nodes](wiki/Managing-Nodes.md): change node settings and restart Reticulum from the Manage page

Guides

- [Connecting Nodes](wiki/Connecting-Nodes.md): set up a node's stats page and remote management end to end
- [WireGuard for Nodes](wiki/WireGuard-for-Nodes.md): a private network for the nodes' links and the website's link to each node
