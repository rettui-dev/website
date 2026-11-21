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

**The Manage page says the node's clock is off, or every request is refused.** The website and the node disagree by more than the allowed time. From one minute off the page warns. From five minutes off the node refuses every request. Fix the time on whichever host is wrong, for example with `timedatectl set-ntp true`.
