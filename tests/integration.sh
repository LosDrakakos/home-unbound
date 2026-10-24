#!/usr/bin/env bash
set -euo pipefail

image=home-unbound:test
name="home-unbound-test-${RANDOM}"
volume="home-unbound-test-${RANDOM}"
password='integration-secret'
tmp_dir=$(mktemp -d)
cookie_jar="$tmp_dir/cookies"
rootfs_container=''
compose_project="home-unbound-it-${RANDOM}-${RANDOM}"
compose_started=0
compose_dns_port=${TEST_COMPOSE_DNS_PORT:-15353}
compose_ui_port=${TEST_COMPOSE_UI_PORT:-18080}

container_logs() {
  local container=$1
  docker logs "$container" 2>&1 || true
}

compose_run() {
  env -u UI_PASSWORD \
    IMAGE="$image" \
    DNS_BIND=127.0.0.1 \
    DNS_PORT="$compose_dns_port" \
    UI_BIND=127.0.0.1 \
    UI_PORT="$compose_ui_port" \
    docker compose -p "$compose_project" "$@"
}

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if (( status != 0 )); then
    container_logs "$name"
    if (( compose_started )); then
      compose_run logs --no-color
    fi
  fi
  if (( compose_started )); then
    compose_run down -v >/dev/null 2>&1
  fi
  if [[ -n "$rootfs_container" ]]; then
    docker rm -fv "$rootfs_container" >/dev/null 2>&1
  fi
  docker rm -f "$name" >/dev/null 2>&1
  docker volume rm "$volume" >/dev/null 2>&1
  rm -rf "$tmp_dir"
  exit "$status"
}
trap cleanup EXIT

need() {
  command -v "$1" >/dev/null || {
    echo "missing required tool: $1" >&2
    exit 1
  }
}

fail_output() {
  local label=$1
  local expected=$2
  local actual=$3
  printf 'FAILED: %s\nexpected: %s\nactual output:\n%s\n' "$label" "$expected" "$actual" >&2
  return 1
}

assert_equal() {
  local label=$1
  local expected=$2
  local actual=$3
  [[ "$actual" == "$expected" ]] || fail_output "$label" "$expected" "$actual"
}

assert_nonempty() {
  local label=$1
  local actual=$2
  [[ -n "$actual" ]] || fail_output "$label" 'non-empty output' "$actual"
}

assert_empty() {
  local label=$1
  local actual=$2
  [[ -z "$actual" ]] || fail_output "$label" 'empty output' "$actual"
}

assert_matches() {
  local label=$1
  local pattern=$2
  local actual=$3
  grep -Eq "$pattern" <<<"$actual" || fail_output "$label" "regular expression: $pattern" "$actual"
}

assert_not_matches_ci() {
  local label=$1
  local pattern=$2
  local actual=$3
  if grep -Eiq "$pattern" <<<"$actual"; then
    fail_output "$label" "no match for regular expression: $pattern" "$actual"
  fi
}

run_dig() {
  local label=$1
  shift
  local output
  if ! output=$(dig "$@" 2>&1); then
    fail_output "$label" 'dig command to succeed' "$output"
    return 1
  fi
  printf '%s' "$output"
}

wait_healthy() {
  local container=$1
  local state=''
  local deadline=$((SECONDS + 120))
  while (( SECONDS < deadline )); do
    state=$(docker inspect "$container" --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' 2>/dev/null || true)
    if [[ "$state" == healthy ]]; then
      return 0
    fi
    sleep 1
  done
  printf 'container %s did not become healthy within 120 seconds (last state: %s)\n' "$container" "$state" >&2
  return 1
}

discover_ports() {
  local ports
  ports=$(docker port "$name")
  dns_udp=$(awk '$1 == "53/udp" { address=$3; sub(/^.*:/, "", address); print address; exit }' <<<"$ports")
  dns_tcp=$(awk '$1 == "53/tcp" { address=$3; sub(/^.*:/, "", address); print address; exit }' <<<"$ports")
  ui=$(awk '$1 == "8080/tcp" { address=$3; sub(/^.*:/, "", address); print address; exit }' <<<"$ports")
  assert_nonempty 'discover UDP DNS port' "$dns_udp"
  assert_nonempty 'discover TCP DNS port' "$dns_tcp"
  assert_nonempty 'discover UI port' "$ui"
  api="http://127.0.0.1:$ui/api"
  ui_url="http://127.0.0.1:$ui"
}

assert_no_fd_warnings() {
  local container=$1
  local output
  output=$(container_logs "$container")
  assert_not_matches_ci "no file-descriptor/source-port warning in $container logs" \
    'too many file descriptors|less udp ports|rlimit' "$output"
}

for tool in docker dig curl jq; do
  need "$tool"
done

docker build -t "$image" .

upstream_index="$tmp_dir/unbound-index.html"
curl -fsSL --proto '=https' --tlsv1.2 --retry 3 \
  -o "$upstream_index" https://nlnetlabs.nl/downloads/unbound/
FETCH_UNBOUND_SOURCE_ONLY=1 . "$PWD/build/fetch-unbound.sh"
unset FETCH_UNBOUND_SOURCE_ONLY
upstream_version=$(select_latest_version "$upstream_index")
unbound_version_output=$(docker run --rm --entrypoint /usr/local/sbin/unbound "$image" -V 2>&1)
built_version=$(awk '$1 == "Version" && $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+$/ { print $2; exit }' <<<"$unbound_version_output")
assert_nonempty 'read built Unbound version' "$built_version"
assert_equal 'image uses latest upstream stable Unbound' "$upstream_version" "$built_version"

if docker run --rm --entrypoint /bin/sh "$image" -c true 2>/dev/null; then
  echo 'final image unexpectedly contains /bin/sh' >&2
  exit 1
fi

layers=$(docker image inspect "$image" --format '{{len .RootFS.Layers}}')
assert_matches 'image layer count is numeric' '^[0-9]+$' "$layers"
(( layers <= 2 )) || fail_output 'scratch layer count' 'at most 2' "$layers"

rootfs_container=$(docker create "$image")
rootfs_bytes=$(docker export "$rootfs_container" | wc -c)
docker rm -v "$rootfs_container" >/dev/null
rootfs_container=''
printf 'image layers=%s exported-rootfs=%s bytes\n' "$layers" "$rootfs_bytes"
assert_matches 'exported rootfs size is numeric' '^[[:space:]]*[0-9]+$' "$rootfs_bytes"
(( rootfs_bytes < 30000000 )) || fail_output 'exported rootfs size' 'less than 30000000 bytes' "$rootfs_bytes"

history=$(docker history --no-trunc "$image")
assert_not_matches_ci 'scratch image history' 'alpine' "$history"

docker volume create "$volume" >/dev/null
docker run -d --name "$name" --read-only --tmpfs /run/unbound:uid=10053,gid=10053,mode=0750 \
  -v "$volume:/data" -e "UI_PASSWORD=$password" \
  -p 127.0.0.1::53/udp -p 127.0.0.1::53/tcp -p 127.0.0.1::8080/tcp "$image" >/dev/null

uid=$(docker inspect "$name" --format '{{.Config.User}}')
assert_equal 'container user' '10053:10053' "$uid"
discover_ports
wait_healthy "$name"
assert_no_fd_warnings "$name"

output=$(run_dig 'recursive UDP lookup' @127.0.0.1 -p "$dns_udp" example.com A +short)
assert_nonempty 'recursive UDP lookup' "$output"
output=$(run_dig 'recursive TCP lookup' @127.0.0.1 -p "$dns_tcp" +tcp example.com A +short)
assert_nonempty 'recursive TCP lookup' "$output"
output=$(run_dig 'DNSSEC-valid lookup' @127.0.0.1 -p "$dns_udp" +dnssec isc.org SOA)
assert_matches 'DNSSEC-valid lookup has AD flag' 'flags:.* ad[ ;]' "$output"
output=$(run_dig 'DNSSEC-bogus lookup' @127.0.0.1 -p "$dns_udp" dnssec-failed.org A)
assert_matches 'DNSSEC-bogus lookup returns SERVFAIL' 'status: SERVFAIL' "$output"

forwards=$(docker exec "$name" /usr/local/bin/unbound-manager ctl list_forwards)
assert_empty 'recursive resolver has no forwarders' "$forwards"
infra=$(docker exec "$name" /usr/local/bin/unbound-manager ctl dump_infra)
assert_nonempty 'recursive resolver contacted authoritative infrastructure' "$infra"
if ! checkconf_output=$(docker exec "$name" /usr/local/sbin/unbound-checkconf /etc/unbound/unbound.conf 2>&1); then
  fail_output 'unbound-checkconf in final image' 'successful validation' "$checkconf_output"
fi

status=$(curl -sS -o /dev/null -w '%{http_code}' "$api/records")
assert_equal 'API requires authentication' '401' "$status"

post_record() {
  curl -fsS -u "admin:$password" -H 'Content-Type: application/json' -d "$1" "$api/records"
}

post_zone() {
  curl -fsS -u "admin:$password" -H 'Content-Type: application/json' -d "$1" "$api/zones"
}

response=$(post_record '{"name":"nas.home.arpa","type":"A","value":"192.168.77.10","ptr":true}')
rid=$(jq -r .id <<<"$response")
assert_matches 'created record ID' '^[0-9a-f]{32}$' "$rid"
post_record '{"name":"nas6.home.arpa","type":"AAAA","value":"fd00::10"}' >/dev/null
post_record '{"name":"alias.home.arpa","type":"CNAME","value":"nas.home.arpa"}' >/dev/null
post_record '{"name":"text.home.arpa","type":"TXT","value":"hello world"}' >/dev/null
post_record '{"name":"mailzone.home.arpa","type":"MX","preference":10,"exchange":"mail.home.arpa"}' >/dev/null
post_record '{"name":"_sip._tcp.home.arpa","type":"SRV","priority":1,"weight":5,"port":5060,"target":"sip.home.arpa"}' >/dev/null
post_record '{"name":"10.0.0.53","type":"PTR","value":"dns.home.arpa"}' >/dev/null
post_record '{"name":"override-test.example.com","type":"A","value":"10.9.8.7"}' >/dev/null
post_zone '{"name":"blocked.example","type":"always_nxdomain"}' >/dev/null
post_zone '{"name":"lab.internal","type":"static"}' >/dev/null
post_record '{"name":"host.lab.internal","type":"A","value":"192.168.50.5"}' >/dev/null
post_zone '{"name":"wild.internal","type":"redirect"}' >/dev/null
post_record '{"name":"wild.internal","type":"A","value":"192.168.60.6"}' >/dev/null

output=$(run_dig 'A record' @127.0.0.1 -p "$dns_udp" nas.home.arpa A +short)
assert_equal 'A record' '192.168.77.10' "$output"
output=$(run_dig 'AAAA record' @127.0.0.1 -p "$dns_udp" nas6.home.arpa AAAA +short)
assert_equal 'AAAA record' 'fd00::10' "$output"
output=$(run_dig 'CNAME record' @127.0.0.1 -p "$dns_udp" alias.home.arpa CNAME +short)
assert_equal 'CNAME record' 'nas.home.arpa.' "$output"
output=$(run_dig 'TXT record' @127.0.0.1 -p "$dns_udp" text.home.arpa TXT +short)
assert_matches 'TXT record' 'hello world' "$output"
output=$(run_dig 'MX record' @127.0.0.1 -p "$dns_udp" mailzone.home.arpa MX +short)
assert_equal 'MX record' '10 mail.home.arpa.' "$output"
output=$(run_dig 'SRV record' @127.0.0.1 -p "$dns_udp" _sip._tcp.home.arpa SRV +short)
assert_equal 'SRV record' '1 5 5060 sip.home.arpa.' "$output"
output=$(run_dig 'automatic PTR' @127.0.0.1 -p "$dns_udp" -x 192.168.77.10 +short)
assert_equal 'automatic PTR' 'nas.home.arpa.' "$output"
output=$(run_dig 'explicit PTR' @127.0.0.1 -p "$dns_udp" -x 10.0.0.53 +short)
assert_equal 'explicit PTR' 'dns.home.arpa.' "$output"
output=$(run_dig 'public-name override' @127.0.0.1 -p "$dns_udp" override-test.example.com A +short)
assert_equal 'public-name override' '10.9.8.7' "$output"
output=$(run_dig 'NXDOMAIN zone' @127.0.0.1 -p "$dns_udp" ads.blocked.example A)
assert_matches 'NXDOMAIN zone' 'status: NXDOMAIN' "$output"
output=$(run_dig 'static-zone record' @127.0.0.1 -p "$dns_udp" host.lab.internal A +short)
assert_equal 'static-zone record' '192.168.50.5' "$output"
output=$(run_dig 'static-zone missing name' @127.0.0.1 -p "$dns_udp" missing.lab.internal A)
assert_matches 'static-zone missing name' 'status: NXDOMAIN' "$output"
output=$(run_dig 'redirect-zone descendant' @127.0.0.1 -p "$dns_udp" anything.wild.internal A +short)
assert_equal 'redirect-zone descendant' '192.168.60.6' "$output"

status=$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE "$api/records/$rid")
assert_equal 'record DELETE requires authentication' '401' "$status"
curl -fsS -u "admin:$password" -X DELETE "$api/records/$rid" >/dev/null
output=$(run_dig 'deleted A record' @127.0.0.1 -p "$dns_udp" nas.home.arpa A +short)
assert_empty 'deleted A record' "$output"
output=$(run_dig 'auto-PTR removed with A record' @127.0.0.1 -p "$dns_udp" -x 192.168.77.10 +short)
assert_empty 'auto-PTR removed with A record' "$output"

status=$(curl -sS -u "admin:$password" -H 'Content-Type: application/json' \
  -d '{"name":"bad\nname","type":"A","value":"192.0.2.1"}' -o /dev/null -w '%{http_code}' "$api/records")
assert_matches 'newline injection rejected' '^4[0-9][0-9]$' "$status"
status=$(curl -sS -u "admin:$password" -H 'Content-Type: application/json' \
  -d '{"name":"bad.home","type":"TXT","value":"bad\"text"}' -o /dev/null -w '%{http_code}' "$api/records")
assert_matches 'quote injection rejected' '^4[0-9][0-9]$' "$status"
output=$(run_dig 'resolver survives injection attempts' @127.0.0.1 -p "$dns_udp" example.com A +short)
assert_nonempty 'resolver survives injection attempts' "$output"

login_html=$(curl -fsS -c "$cookie_jar" "$ui_url/login")
[[ "$login_html" == *'Unbound Manager'* ]] || fail_output 'login page content' 'Unbound Manager' "$login_html"
status=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Origin: null' -H 'Sec-Fetch-Site: cross-site' \
  --data-urlencode "password=$password" "$ui_url/login")
assert_equal 'browser cross-site login rejected' '403' "$status"
status=$(curl -sS -o /dev/null -w '%{http_code}' -b "$cookie_jar" -c "$cookie_jar" \
  -H 'Origin: null' -H 'Sec-Fetch-Site: same-origin' \
  --data-urlencode "password=$password" "$ui_url/login")
assert_equal 'browser same-origin login with null Origin redirects' '303' "$status"
records_html=$(curl -fsS -b "$cookie_jar" "$ui_url/records")
csrf=$(awk 'match($0, /name="csrf_token" value="[^"]+"/) { value=substr($0, RSTART, RLENGTH); sub(/^.*value="/, "", value); sub(/"$/, "", value); print value; exit }' <<<"$records_html")
assert_nonempty 'records form CSRF token' "$csrf"
status=$(curl -sS -o /dev/null -w '%{http_code}' -b "$cookie_jar" \
  --data-urlencode 'name=missing-token.home.arpa' --data-urlencode 'type=A' \
  --data-urlencode 'value=192.168.77.21' "$ui_url/records")
assert_equal 'browser form rejects missing CSRF token' '403' "$status"
status=$(curl -sS -o /dev/null -w '%{http_code}' -b "$cookie_jar" \
  -H 'Origin: null' -H 'Sec-Fetch-Site: same-origin' \
  --data-urlencode "csrf_token=$csrf" --data-urlencode 'name=form.home.arpa' --data-urlencode 'type=A' \
  --data-urlencode 'value=192.168.77.20' --data-urlencode 'ptr=on' "$ui_url/records")
assert_equal 'browser record creation redirect' '303' "$status"
output=$(run_dig 'browser-created A record' @127.0.0.1 -p "$dns_udp" form.home.arpa A +short)
assert_equal 'browser-created A record' '192.168.77.20' "$output"
output=$(run_dig 'browser-created automatic PTR' @127.0.0.1 -p "$dns_udp" -x 192.168.77.20 +short)
assert_equal 'browser-created automatic PTR' 'form.home.arpa.' "$output"

docker restart "$name" >/dev/null
discover_ports
wait_healthy "$name"
assert_no_fd_warnings "$name"
output=$(run_dig 'record persists after restart' @127.0.0.1 -p "$dns_udp" override-test.example.com A +short)
assert_equal 'record persists after restart' '10.9.8.7' "$output"
login_html=$(curl -fsS "$ui_url/login")
[[ "$login_html" == *'Unbound Manager'* ]] || fail_output 'login page after restart' 'Unbound Manager' "$login_html"
status=$(curl -sS -o /dev/null -w '%{http_code}' "$ui_url/records")
assert_equal 'unauthenticated records page redirects' '303' "$status"

compose_started=1
compose_run up -d --no-build --wait
compose_container=$(compose_run ps -q unbound)
assert_nonempty 'compose service container ID' "$compose_container"
assert_no_fd_warnings "$compose_container"
compose_password=$(docker exec "$compose_container" /usr/local/bin/unbound-manager password)
assert_nonempty 'compose generated UI password' "$compose_password"
output=$(run_dig 'compose recursive lookup' @127.0.0.1 -p "$compose_dns_port" example.com A +short)
assert_nonempty 'compose recursive lookup' "$output"
login_html=$(curl -fsS "http://127.0.0.1:$compose_ui_port/login")
[[ "$login_html" == *'Unbound Manager'* ]] || fail_output 'compose UI login page' 'Unbound Manager' "$login_html"
status=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Origin: null' -H 'Sec-Fetch-Site: same-origin' \
  --data-urlencode "password=$compose_password" "http://127.0.0.1:$compose_ui_port/login")
assert_equal 'compose login with generated password' '303' "$status"
compose_run down -v
compose_started=0

echo 'integration tests passed'
