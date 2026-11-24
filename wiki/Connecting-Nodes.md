How to connect a rettui node to your website, end to end. There are two separate links, and you can set up either one without the other:

- **The stats page.** The node publishes a read-only `stats.json`, and the website shows its numbers on the status page. See [Node Stats](Node-Stats).
- **Remote management.** Users with the right role change a few of the node's settings, and restart its Reticulum, on the website's Manage page. See [Managing Nodes](Managing-Nodes).

This page is the checklist that joins the two sides. It does not repeat what the other pages explain: it links to them. The examples use a node called Front at `front.rns.rettui.dev:4242`, reached at the private address `10.77.1.1`. To build the private network that address lives on, see [WireGuard for Nodes](WireGuard-for-Nodes).

## What you need

- A rettui node, started as `rettui node` (in Docker, `command: node`), on a version that has remote management. The image tag matters: see Troubleshooting below.
- The website running with a config file (`CONFIG_FILE`). Nodes with `stats_url` or `manage_url` are listed in it. See [Configuration](Configuration#config-file).
- A private link between the website and the node for management: a WireGuard tunnel (see [WireGuard for Nodes](WireGuard-for-Nodes)), or a TLS proxy. The node speaks plain http.

## 1. The node side

The flags and the Docker variables do the same thing. The Docker variables work with the image's entrypoint, and the management ones only with the `node` command. The node's own pages are [Hosting a Node](https://github.com/rettui-dev/rettui/wiki/Hosting-a-Node) (the stats page is under "A stats page for a status page", management under "Remote management") and [Docker](https://github.com/rettui-dev/rettui/wiki/Docker).

### Stats page

| Flag | Docker variable | What it does |
|---|---|---|
| `--stats-listen ADDRESS` | `STATS_LISTEN` | Serves `/stats.json` on this address, for example `0.0.0.0:8741` in Docker. Off unless given. |
| `--stats-token-file PATH` | `STATS_TOKEN_FILE` | A secret that lets a request also get the peer lists. Needs the stats listener. |
| `--stats-logs` | `STATS_LOGS=1` | Lets the token also read the end of the log, for the website's Logs tab. Needs the stats listener and a token. |

The stats page has no login. Publish it only to a reverse proxy (for example `"127.0.0.1:8741:8741"` under `ports:`) or on a tunnel address, never to the internet.

### Remote management

| Flag | Docker variable | What it does |
|---|---|---|
| `--manage-listen ADDRESS` | `MANAGE_LISTEN` | Where the node takes the website's signed requests, for example `0.0.0.0:8750` in Docker. Needs a secret file. |
| `--manage-secret-file PATH` | `MANAGE_SECRET_FILE` | The file with the node's secret. There is no variable for the secret itself. |
| `--manage-allow ADDRESS` | `MANAGE_ALLOW` | Takes management connections only from this address or network. In Docker, several, separated by commas. |
| `--manage-allow-enable` | `MANAGE_ALLOW_ENABLE=yes` | Lets a Reticulum change from the website turn interfaces and Transport on, which opens the node to others. Off unless given. |
| `--manage-reticulum-changes N` | `MANAGE_RETICULUM_CHANGES` | The most Reticulum changes the website may make in the hours below (1 to 100, default 4). |
| `--manage-reticulum-hours H` | `MANAGE_RETICULUM_HOURS` | The hours that count for the limit above (1 to 168, default 1). |

None of these are saved: give them on every start. Without `--manage-allow` any address that can reach the port can take its connection places, and the node warns at start. Treat `MANAGE_ALLOW` as required.

### Docker Compose example

```yaml
services:
  rettui:
    image: ghcr.io/rettui-dev/rettui:latest
    command: node
    environment:
      STATS_LISTEN: 0.0.0.0:8741
      STATS_TOKEN_FILE: /run/secrets/stats_token
      MANAGE_LISTEN: 0.0.0.0:8750
      MANAGE_SECRET_FILE: /run/secrets/manage_secret
      MANAGE_ALLOW: 10.77.1.2
    ports:
      - "4242:4242"
      - "10.77.1.1:8741:8741"      # the node's tunnel address only (or 127.0.0.1 for a reverse proxy)
      - "10.77.1.1:8750:8750"      # the node's tunnel address only
    secrets:
      - stats_token
      - manage_secret
secrets:
  stats_token:
    file: ./secrets/front.token
  manage_secret:
    file: ./secrets/front.manage
```

Inside the container the node listens on `0.0.0.0` and warns about it. That is expected: the `ports:` line is what keeps the port private. Never publish 8750 as `"8750:8750"`. When it starts, the node prints `Remote management at http://…/manage/v1/ (signed requests only, from … only)`.

## 2. Make the secrets

Each node needs two secrets, both different from each other, and a secret of its own for every node.

| Secret | Length and characters | Used by |
|---|---|---|
| Stats token | 16 to 256 printable ASCII characters, no spaces, quotes or backslash | `stats_token_file` on the website, `STATS_TOKEN_FILE` on the node |
| Manage secret | 32 to 256 printable ASCII characters, no spaces, quotes or backslash | `manage_secret_file` on the website, `MANAGE_SECRET_FILE` on the node |

Make them on the website host, one file each, and copy the same file to the node:

```sh
mkdir -p secrets && umask 077
openssl rand -hex 32 > secrets/front.manage
openssl rand -hex 32 > secrets/front.token
chmod 600 secrets/front.manage secrets/front.token
```

Rules:

- The file must be readable and writable by its owner only (`chmod 600`). On Linux and macOS both the website and the node stop at start if the group or others can read or write a manage secret file.
- With Docker, give the file to the user the container runs as. On the website that is uid 1000 (`sudo chown 1000 secrets/front.manage`). On a rettui node it is the user set by `PUID`. A Compose file secret keeps the owner and mode of the host file.
- A manage secret must never be the same as a stats token. Two nodes with the same manage secret are refused too.
- The secrets are read once at start. Restart to change one.

## 3. The website side

In the website's config file, add the node. A relative path is relative to the config file. With Docker, mount the folder (`./secrets:/config/secrets:ro`).

```yaml
nodes:
  - address: front.rns.rettui.dev:4242
    name: Front
    stats_url: http://10.77.1.1:8741/stats.json
    stats_token_file: secrets/front.token
    manage_url: http://10.77.1.1:8750
    manage_secret_file: secrets/front.manage
    manage_confirm_seconds: 300
```

| Key | Meaning |
|---|---|
| `stats_url` | Where to fetch the node's `stats.json`. `https`, or plain `http` to a loopback or private address. |
| `stats_token_file` | The stats token. Needs `stats_url`. |
| `manage_url` | The node's management listener: an origin only (`http://host:port`, no path, query or fragment). |
| `manage_secret_file` | The manage secret. `manage_url` and `manage_secret_file` go together: one without the other stops the server at start. |
| `manage_confirm_seconds` | 60 to 900, default 300. How long the node waits for the website to confirm a Reticulum change. Needs `manage_url`. |

There are no environment variables for the manage keys. Restart the website after changing the file. If the site has no users yet, it warns at start that nobody can manage the node until a user with the `manage` or `admin` role exists.

### Which addresses plain http may go to

Both URLs use `https` for any address. Plain `http` is accepted only to a literal IP address or `localhost`, never to a host name:

| Key | Plain http allowed to |
|---|---|
| `stats_url` | loopback (`127/8`, `::1`, `localhost`), `10/8`, `172.16/12`, `192.168/16` |
| `manage_url` | the same, and also the shared range `100.64/10`, `fc00::/7` (WireGuard over IPv6) and `fe80::/10` |

A host name in `manage_url` needs `https`. The stats list is narrower because the stats token travels with every request.

## 4. Users, roles and two-step sign-in

Only signed-in users with the role `manage` or `admin` can use the Manage page.

1. Make an admin if the site has none. See [Managing Users](Managing-Users) ("The first admin").
2. On the Users page, give the people who manage nodes the role `manage`.
3. Each of them turns on two-step sign-in on their Account page. See [Accounts and Second Factor](Accounts-and-Second-Factor).

Two things to plan for:

- A first second factor starts a 24 hour wait. For those 24 hours the user can look at nodes but not change them.
- Once any node has a `manage_url`, admins need two-step sign-in on to change users, and the same 24 hour wait applies. Turn it on for admins before you add the first `manage_url`.

The site needs a user store key as soon as it has users. See [User Store](User-Store).

## 5. Open the Manage page

Sign in, then open `/manage`, or use the "Manage nodes" link on your Account page. The cookie is `Secure`, so the site has to be served over https (or be `localhost`). See [Logins](Logins#behind-a-reverse-proxy).

Pick the node from the list. A working link shows the node's version, whether Reticulum is running and how many interfaces are online, and whether its clock agrees with the website's. What you can change, and the safeguards around it, are in [Managing Nodes](Managing-Nodes).

## Links between nodes

The status page draws which monitored node dials which: arrows on the network map and "Dials", "Dialled by" and "Linked with" chips on the cards.

**Found by the website (`detect_links`).** This is off until you set `detect_links: true` at the top of the config file, and it needs at least one user, so that there is a sign-in to keep the links behind. When it is on, for every node with a `manage_url`, the website reads the node's redacted Reticulum config (the read-only view the Manage page shows) every 5 minutes, one signed `GET` of the node's state, as the actor `status-links`. That is 12 reads an hour for a node, apart from the 120 reads an hour each user has on the Manage page and far below what the node accepts. It never happens for a page view: visitors only get the last result from memory. A client interface (one with a `target_host` and a `target_port`) whose target is another monitored node means "this node dials that node". The target is matched in this order, host without regard to case and port as a number:

1. the host and port are the other node's `address`;
2. the host is the host of the other node's `manage_url` (the port may differ);
3. the host is the host of the other node's `stats_url`, but only when that host is not the address host of any monitored node (a shared host does not tell the nodes apart).

With the WireGuard setup of [WireGuard for nodes](WireGuard-for-Nodes), Front has an interface to `10.77.2.1` port 4243, and Back's `manage_url` is `http://10.77.2.1:8750`. The ports differ, so step 2 matches on the host alone and the page shows "Front dials Back". A target that matches no monitored node is dropped on the server, a node never links to itself, and a host that matches more than one node is not guessed: it is dropped (start the server with `LINKS_DEBUG=1` to log that, without addresses). An interface is on when its `enabled` or `interface_enabled` is true (`true`, `yes`, `on` or `1`), the same rule Reticulum uses, and off when neither key is true; an interface with neither key is off. The node's redacted view shows only `yes`, `no`, `true`, `false`, `on` and `off`, so a value of `1` or `0` is shown as not known. An interface that is off shows as "turned off".

A detected link is the dialling node's own claim: it says that node is set to connect to that address, not that the connection works or that the node at that address agrees.

A node that cannot be read (down, wrong secret, an older node without the Reticulum view, a shared Reticulum instance) gives no detected links; the last good result is kept for 15 minutes and then dropped. Reading never delays the checks, the Manage page or anyone's changes. After a failed read the website waits longer before it tries again (2, then 4, up to 6 intervals), and it writes one line to the log when a node's links cannot be read and one when they can be again, with the node's name and an error code, never an address. The reads use the user name `status-links`, which no user can be given. A link is left out of the page when either of its nodes has `links` locked. A detected link is also left out for visitors who are not signed in when either of its nodes has `public_details: false`: the one that dials and the one that is dialled. Visitors who are not signed in get each link's node and direction only, not whether the node's own config says the interface is on, and not where the link came from; signed-in users get all of it. When `detect_links` is on and a `require_login` list (at the top level or for a node) leaves out `links`, the website warns at start: the list replaces the default, so those links are shown to everyone.

**Declared by you.** For a node without `manage_url`, or a link its config does not show, add `links` to the node in the config file:

```yaml
nodes:
  - address: front.rns.rettui.dev:4242
    name: Front
    links:
      - to: Back
      - to: side.rns.rettui.dev:4242
        direction: unknown
```

`to` is the name or the address of another node in the file. `direction` is `dials` (the default: this node connects out to it) or `unknown`, which is drawn as a line with a hollow circle at each end and worded "linked with". If both are there for the same node, the node's config wins: the links it dials are shown as found, and a declared link that its complete config does not show is drawn as declared, with "declared; not found in the node's config". A node's config only speaks for the links that node dials: if Back is declared to dial Hostile and Hostile's config says it dials Back, both are shown, each on the card of the node that dials.

**What is published.** `/api/status` gives each node a `links` list with, for each link, only the other node's `host:port` (as it already names nodes), `dir` (`dials` or `unknown`), `enabled` (`true`, `false` or `null` when not known), `source` (`detected` or `declared`) and `conflict` (`null`, `direction` or `not_found`), at most 8 per node. Interface names, target hosts, WireGuard addresses and manage or stats URLs never leave the server, and the [public API](Public-Data-and-Stats-API) does not have links. Visitors who are not signed in get only `to`, `dir` and `enabled`; `source` and `conflict` are for signed-in users. `links` is part of the default `require_login`, so once there are users the links are for signed-in users only, until you write a `require_login` list without `links`. **Turning on `detect_links` publishes which of your nodes dials which, and whether that interface is on, to everyone who may see links.** The node configs behind it were set up for management, not for publication, so look at the result before you open the links to everyone (see [Logins](Logins#logins)).

## Troubleshooting

These assume the WireGuard layout from [WireGuard for Nodes](WireGuard-for-Nodes), with its example addresses: the node's server address is `10.77.1.1` and the website host's address in that network is `10.77.1.2`. Work down the list: each step rules out the one before it.

**`sudo wg show` on the website host shows no "latest handshake" for the node.** The tunnel itself is not up, so nothing else can work.

- UDP 51820 is not open on the node host or at its provider. Open it for the website host's public address.
- The keys are crossed. Each side's `[Peer]` holds the *other* host's public key, and each `[Interface]` its own private key.
- `Endpoint` in the client file is not the node's public address and port.
- The client's `Address` is not the one the server allows. The server's `AllowedIPs` for that peer must be exactly the client's address, for example `10.77.1.2/32`.
- The interface is not running: `sudo systemctl status wg-quick@wg-front`.

**There is a handshake, but `ping 10.77.1.1` gets no answer.** `AllowedIPs` in the client file must hold the server's address (`10.77.1.1/32`). Also check that no other network on the host uses the same range (`ip route`, `docker network inspect`): an overlapping Docker network takes the packets first.

**The tunnel drops after a while and comes back when the node is pinged.** The client is behind NAT and the mapping timed out. Set `PersistentKeepalive = 25` in the client's `[Peer]`.

**`ping 10.77.1.1` works, but `nc -vz 10.77.1.1 8750` is refused or times out.** The tunnel is fine and the port is not there.

- The node's compose file does not publish the port on the tunnel address. It needs `"10.77.1.1:8750:8750"` under `ports:`, and `MANAGE_LISTEN: 0.0.0.0:8750`.
- The node did not start its listener. It prints `Remote management at …` at start. If it does not, check the image tag (branch images replace `/` with `-`: branch `feature/x` is the tag `feature-x`) and that the container runs `command: node`.

**The node's container fails to start with "cannot assign requested address".** Docker tried to publish a port on `10.77.1.1` before `wg0` existed, or the address in `ports:` is not the one in `wg0.conf`. Compare the two, and make Docker start after WireGuard (the `systemctl edit docker` step in [WireGuard for Nodes](WireGuard-for-Nodes#4-publish-the-nodes-private-ports-on-the-tunnel-address-only)).

**`nc` connects, but the Manage page cannot reach the node, and the node's log says it turned a connection away.** `MANAGE_ALLOW` is not the address the node sees. Through the tunnel that is the website host's tunnel address, `10.77.1.2`, not the website's public address and not its container's address. The node's log names the address it turned away (at most once a minute): put that one in `MANAGE_ALLOW`.

**The website stops at start and the message names a host or plain http.** `manage_url` must be the tunnel address itself, `http://10.77.1.1:8750`. A host name is refused over plain http, even one that resolves to the tunnel address.

**A node's log shows "Backbone …: TCP connect failed: timed out".** That node is the client of the other node's server. On the dialling node, check the handshake for that tunnel (`sudo wg show wg-back`), then `nc -vz 10.77.2.1 4243`. The interface's `target_host` must be the other node's server address, and the other node must publish 4243 on that address.

**The website or the node stops at start and the message says the secret file can be read or changed by other users.** Run `chmod 600` on the file. In Docker, also check its owner (see Make the secrets above).

**The website refuses to start with the same secret for two nodes, or a manage secret that is also a stats token.** Make a new secret for each. See step 2.

**`/manage` answers 404.** The signed-in user does not have the role `manage` or `admin`, nobody is signed in, or the user still has to change a password an admin set. A viewer gets 404 on purpose.

**Changes are refused with a 403.** The user has not turned on two-step sign-in, or it is less than 24 hours since they turned on their first one. See step 4.

**A Reticulum change is refused with "The node is still making its announce stamp".** A new node makes a proof of work (the announce stamp) that Reticulum needs before it can answer the test that follows a change. Nothing was changed. The website does not retry by itself. Wait, then press Apply again. On a new node this can take a few minutes (the node stops waiting after 30 at most), and a new node needs it only once.

**The Manage page says the node's clock is off, or every request is refused.** The website and the node disagree by more than the allowed time. From one minute off the page warns. From five minutes off the node refuses every request. Fix the time on whichever host is wrong, for example with `timedatectl set-ntp true`.
