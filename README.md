# Home Unbound

Home Unbound is a small, single-container recursive DNS resolver with DNSSEC validation and a password-protected management UI. It asks the DNS root and authoritative servers directly: the shipped configuration has no forwarders, stub zones, or upstream recursive resolver that can alter answers.

The final image is built `FROM scratch`. It contains statically linked, stripped Unbound tools and a statically linked Go manager; there is no shell or libc. Both Unbound and the manager run as UID/GID `10053`.

## Quick start

```sh
docker compose up -d --build
docker compose logs unbound
```

The first start generates an admin password, writes it to `/data/manager/ui-password` with mode `0600`, and prints it once. Later starts log only the file location. Open <http://127.0.0.1:8080/>. To supply a password instead, set `UI_PASSWORD`, or mount a secret and set `UI_PASSWORD_FILE`.

Compose publishes DNS on host TCP and UDP port 53, while the UI is bound to localhost only. Resolver data and UI credentials persist in the `unbound-data` volume. The root filesystem is read-only; `/run/unbound` is a UID-10053 tmpfs.

Host port 53 may already be occupied by the `systemd-resolved` stub or another local resolver. Stop or reconfigure the conflicting service, or choose another bind address/port. Compose accepts `DNS_BIND`, `DNS_PORT`, `UI_BIND`, `UI_PORT`, and `IMAGE` overrides:

```sh
DNS_BIND=127.0.0.1 DNS_PORT=1053 UI_PORT=18080 docker compose up -d --build
dig @127.0.0.1 -p 1053 example.com
```

The UI provides:

- resolver status, uptime, cache/query statistics, and an explicit recursive/no-forwarders indicator;
- A, AAAA, CNAME, TXT, MX, SRV, and PTR records;
- automatic PTR creation for A/AAAA records and a consolidated reverse-DNS view;
- transparent, static, redirect, NXDOMAIN-block, and REFUSED local zones;
- local DNS lookups showing rcode, answers, and the DNSSEC AD flag;
- generated and live Unbound local configuration; and
- cache and DNSSEC-bogus-cache maintenance actions.

Changes are validated, written atomically, checked with `unbound-checkconf`, and applied with `reload_keep_cache` (falling back to `reload`). A failed check or reload restores the previous store and generated configuration.

## Reverse DNS

For an A or AAAA record, select **Create reverse PTR automatically**. The manager renders an Unbound `local-data-ptr` entry using the same owner name. An explicit PTR accepts either an IP address (the manager converts it to `in-addr.arpa.` or nibble-format `ip6.arpa.`) or a complete reverse owner name. Conflicting automatic and explicit PTRs for the same IP are rejected.

## JSON API

The API accepts HTTP Basic authentication; the username is ignored and the password is the admin password. Session-authenticated writes instead require the session CSRF token in `X-CSRF-Token`. JSON POSTs require `Content-Type: application/json`.

```sh
password='your-password'
curl -u "admin:$password" http://127.0.0.1:8080/api/status

curl -u "admin:$password" -H 'Content-Type: application/json' \
  -d '{"name":"nas.home.arpa","type":"A","value":"192.168.1.20","ptr":true}' \
  http://127.0.0.1:8080/api/records

curl -u "admin:$password" -H 'Content-Type: application/json' \
  -d '{"name":"ads.example","type":"always_nxdomain","comment":"local block"}' \
  http://127.0.0.1:8080/api/zones

curl -u "admin:$password" -X DELETE \
  http://127.0.0.1:8080/api/records/RECORD_ID
```

Routes are `GET/POST /api/records`, `DELETE /api/records/{id}`, `GET/POST /api/zones`, `DELETE /api/zones/{id}`, and `GET /api/status`.

## Command-line control

The manager includes a native client for the Unbound control socket, so the image does not need a separate `unbound-control` binary. Pass a control command and its arguments after `ctl`:

```sh
docker compose exec unbound /usr/local/bin/unbound-manager ctl status
docker compose exec unbound /usr/local/bin/unbound-manager ctl list_forwards
docker compose exec unbound /usr/local/bin/unbound-manager ctl flush_zone example.com.
docker compose exec unbound /usr/local/bin/unbound-manager ctl dump_infra
```

The response is written to standard output; protocol and connection errors are written to standard error and return a nonzero status.

## Custom Unbound configuration

Files in [`config/custom.d`](config/custom.d) are mounted read-only at `/etc/unbound/custom.d`. The included placeholder makes the glob safe when there are no custom settings. Each custom file containing server options must begin with `server:`. Validate additions carefully; the manager refuses to start or apply records if `unbound-checkconf` rejects the complete configuration.

Do not add `forward-zone`, `forward-addr`, or `stub-zone` directives if direct recursion is part of your threat model. The dashboard detects configured forwarders, but arbitrary custom settings remain the operator's responsibility.

## Security notes

- DNS access is refused by default and allowed only from loopback, RFC1918, carrier-grade NAT, link-local, and IPv6 ULA/link-local networks. Do not broaden this into an open resolver.
- The UI has no TLS. Keep its localhost binding, expose it only on a trusted LAN, or put it behind a TLS reverse proxy. The UI uses HttpOnly/SameSite cookies, CSRF and origin checks, login throttling, constant-time password comparison, and restrictive browser headers.
- Input rendered into Unbound configuration or control commands is strictly validated. TXT quotes, backslashes, controls, and newlines are rejected; comments are never rendered.
- The container drops all Linux capabilities. Binding port 53 as non-root works with Docker's usual `net.ipv4.ip_unprivileged_port_start=0` container setting. That setting is not applied with `network_mode: host`; for host networking, lower the host sysctl deliberately or publish a high port/use an external redirect instead.
- `DNS_IPV6=auto` (default) binds IPv6 only if a UDP `[::]:0` probe succeeds. Use `yes` to require/configure it or `no` to disable it.
- `/healthz` and the image healthcheck are intentionally unauthenticated; they reveal only availability.

## Configuration environment

Common container settings are `DATA_DIR` (default `/data`), `UI_LISTEN` (default `:8080`), `UI_ENABLED` (`false` disables the UI), `UI_PASSWORD`, `UI_PASSWORD_FILE`, and `DNS_IPV6=auto|yes|no`. Compose additionally consumes `DNS_BIND`, `DNS_PORT`, `UI_BIND`, `UI_PORT`, and `IMAGE` on the host. Binary and configuration paths also have `UNBOUND_BIN`, `UNBOUND_CHECKCONF_BIN`, `UNBOUND_CONFIG`, `UNBOUND_CONTROL_SOCKET`, `UNBOUND_RUN_DIR`, `UNBOUND_LOCAL_CONFIG`, `UNBOUND_NETWORK_CONFIG`, and `UNBOUND_ROOT_KEY_SEED` overrides for tests.

## Tests

Host prerequisites for the integration suite are Docker, `dig`, `curl`, and `jq`.

```sh
make test-unit        # Go vet and unit tests in the pinned Go container
make build
make test-integration # scratch/image, recursion, DNSSEC, API, records, PTR, persistence
make test             # both suites
```

The Docker build itself runs `go vet ./...` and `go test ./...` before it can build the manager binary.

## Upgrading Unbound

Update both `UNBOUND_VERSION` and `UNBOUND_SHA256` in [`Dockerfile`](Dockerfile). Obtain the release checksum from NLnet Labs, then rebuild and run the complete integration suite. The build verifies the tarball, static linkage, and that the generated RFC 5011 seed includes root KSK tags 20326 and 38696. `unbound-anchor` writes those numeric key IDs in the generated DNSKEY metadata; checking both IDs prevents silently shipping a stale rollover seed.
