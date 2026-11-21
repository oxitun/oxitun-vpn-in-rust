# oxitun

Minimal OpenVPN tunnel container: **HTTP CONNECT proxy + killswitch firewall
+ process supervisor** in a single small static Rust binary.

A lean, single-binary alternative to VPN sidecar images (e.g. Gluetun) for
workloads that only need "traffic out through a specific tunnel" — such as
per-worker egress IPs for high-throughput API clients.

## Features

- **CONNECT proxy** on `0.0.0.0:8888` (HTTPS tunneling; plain-HTTP forward
  proxying intentionally unsupported)
- **`GET /healthz`** on the same port — `200` only while `tun0` exists
  (used by the Docker `HEALTHCHECK`)
- **Killswitch (iptables + ip6tables)**: default-DROP on INPUT/FORWARD/OUTPUT;
  traffic may only leave via `tun0` or the VPN server itself — no IP leaks
  if the tunnel drops
- **Tunnel DNS** pinned to the provider resolver (default `10.2.0.1`,
  ProtonVPN); external DNS is unreachable under the killswitch
- **OpenVPN supervision**: restarts remote failover flags
  (`--connect-retry-max`, `--connect-timeout`, `--hand-window`) so dead
  free-tier servers are skipped instead of hanging forever; the process
  exits when `openvpn` dies → Docker `restart` policy takes over
- **Zero runtime deps beyond `openvpn`**: the supervisor *is* the binary

## Measured footprint (Alpine 3.20, openvpn 2.6)

| | oxitun | Gluetun (reference) |
|---|---|---|
| RSS per container | **~1–8 MiB** | ~35–45 MiB |
| 80 containers total | **~81 MiB** | ~3.0 GiB |

Validated in production with 80 concurrent ProtonVPN tunnels.

## Usage

```bash
docker run -d \
  --name oxitun \
  --cap-add NET_ADMIN \
  --device /dev/net/tun:/dev/net/tun \
  -e VPN_USER='your-user' \
  -e VPN_PASS='your-pass' \
  -v /path/to/profile.ovpn:/etc/openvpn/client.ovpn:ro \
  -p 127.0.0.1:18011:8888 \
  oxitun
```

Then:

```bash
curl -x http://127.0.0.1:18011 https://api.ipify.org   # exit IP of the tunnel
curl http://127.0.0.1:18011/healthz                    # liveness (200 = tun0 up)
```

### docker compose

See `docker-compose.yml` — copy `.env.example` to `.env`, drop `.ovpn`
profiles next to it as `oxitun-1.ovpn` / `oxitun-2.ovpn`, then
`docker compose up -d`.

### Using the published image

The image is published at **`ghcr.io/oxitun/oxitun`** (public GHCR,
anonymous pull works):

```bash
docker pull ghcr.io/oxitun/oxitun:latest
```

`docker ps` shows the **local tag** used at container creation, not the
image author. To display a short name instead of the full registry path,
retag the image locally or build it from source:

```bash
# retag the pulled image
docker tag ghcr.io/oxitun/oxitun:latest oxitun:latest
# then use `oxitun:latest` in `docker run` / compose → shows "oxitun"

# or build it yourself (no registry needed)
git clone https://github.com/oxitun/oxitun-vpn-in-rust.git
cd oxitun-vpn-in-rust
docker build -t oxitun .
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `VPN_USER` | — (required) | VPN username |
| `VPN_PASS` | — (required) | VPN password |
| `VPN_PROFILE` | `/etc/openvpn/client.ovpn` | Path to `.ovpn` profile |
| `PROXY_PORT` | `8888` | CONNECT proxy listen port |
| `VPN_DNS` | `10.2.0.1` | Resolver forced inside the tunnel |
| `KILLSWITCH` | `on` | `off` disables iptables rules (**debug only**) |

Values may be wrapped in single or double quotes — they are stripped.

## Image

The published image is multi-stage (`rust:alpine` → `alpine:3.20`) and only
~15 MB. Runtime packages: `openvpn`, `iptables`, `iproute2`, `tini`.

## Security notes

- The container **requires** `NET_ADMIN` and `/dev/net/tun` — the killswitch
  and tunnel cannot work without them. Do not expose the proxy port beyond
  localhost unless you add your own auth.
- Credentials are written to `/run/oxitun-auth.txt` (mode `0600`, tmpfs)
  and passed to `openvpn --auth-user-pass`; they never appear in logs.
- If the VPN server list in a profile changes, the killswitch allowlist is
  rebuilt from the profile's `remote` directives on every container start.
- `KILLSWITCH=off` exists for debugging only — never use it in production.

## Notes & limitations

- OpenVPN **TCP client** profiles only (e.g. ProtonVPN `.ovpn` files)
- `auth-user-pass` profiles only — no certificates/client-key auth yet
- Plain-HTTP forward proxying is not implemented (CONNECT only)
- Run **one tunnel per container**; scale by running N containers
- Tested with ProtonVPN free-server profiles; other providers unverified
- Free-tier servers are flaky by nature — pair this with an external
  health-check/restart loop if you need automatic profile rotation

## Build

```bash
docker build -t oxitun .
# or locally: cargo build --release
```

## License

MIT — see [LICENSE](LICENSE).
