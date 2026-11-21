The website for [rettui](https://github.com/rettui-dev/rettui): a home page and a
status page that checks the project's Reticulum entry points. It has the same look
as rettui's web UI (colours, Fira Sans and Fira Code, dark and light themes).

It is plain HTML, CSS and JavaScript, served by a small Node.js server
(`server.js`) with no build step and two dependencies (`yaml`, and `@simplewebauthn/server` for
passkeys, see [Passkeys](Accounts-and-Second-Factor#passkeys)). The server also probes the hosts,
keeps their history and can fetch their node stats.

These pages are for people who run the website and rettui nodes.

## Which page answers what

**Getting started**

- [Installing and Running](Installing-and-Running): start the server locally or in Docker
- [Configuration](Configuration): environment variables, the YAML config file, a status-only site and branding
- [Pages and Themes](Pages-and-Themes): every page and endpoint, the Join and Downloads pages, the release feed

**Running a status site**

- [Node Stats](Node-Stats): what the website reads from your nodes: logs, disk and propagation numbers, groups, the network map
- [Uptime and Alerts](Uptime-and-Alerts): the 90 day record, incidents, and alerts by webhook or email
- [Public Data and Stats API](Public-Data-and-Stats-API): what visitors see, and the public JSON API

**Logins and users**

- [Logins](Logins): users in the config file, what is locked for visitors, sessions and lockouts
- [Accounts and Second Factor](Accounts-and-Second-Factor): the account page, app codes, recovery codes and passkeys
- [Managing Users](Managing-Users): the Users page and the `scripts/users.js` command
- [User Store](User-Store): the user database, its key, backups and moving users

**Nodes**

- [Managing Nodes](Managing-Nodes): change a node's settings and restart its Reticulum from the Manage page

**Guides**

- [WireGuard for Nodes](WireGuard-for-Nodes): a private network for the nodes' links and the website's link to each node
- [Connecting Nodes](Connecting-Nodes): set up a node's stats page and remote management end to end, with a troubleshooting list

## Where to start

- To run the site: [Installing and Running](Installing-and-Running), then [Configuration](Configuration).
- To list your own nodes: [Configuration](Configuration#config-file), then [Node Stats](Node-Stats).
- To let people sign in: [Logins](Logins) and [User Store](User-Store).
- To manage nodes from the website: [WireGuard for Nodes](WireGuard-for-Nodes) and [Connecting Nodes](Connecting-Nodes).
