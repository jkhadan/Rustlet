#!/usr/bin/env bash
# scripts/smoke.sh: end-to-end checks against the installed rustletd
# (docs/architecture.md §6). Run as your normal user from the repository,
# with the service installed and running (`cargo xtask daemon install`):
#
#   scripts/smoke.sh            # every check
#   scripts/smoke.sh --keep     # leave the containers, network and volume
#
# It runs the CLI as `sudo -n target/debug/rustlet` (the dev sudoers allows
# it; the API socket is root's without a `rustlet` group). The checks:
#
#   1. run: output and exit status passed through
#   2. a published port: curl through 127.0.0.1 (the proxy) and through
#      the host's own address (DNAT)
#   3. the LAN can't reach a container directly: a throwaway namespace
#      `rlsmoke` plays a LAN host behind a veth (192.0.2.0/24, TEST-NET-1,
#      and 2001:db8:5::/64) with a route to 10.89.0.0/16 through this host;
#      the published port answers it, the container's own address doesn't
#   4. names between containers on a user-defined network
#   5. --ip, and network connect/disconnect on a running container
#   6. an IPv6 network: a published port over IPv6 (the proxy on ::1, DNAT
#      from the host and from the LAN), the guard, AAAA answers
#   7. --network container:X shares X's localhost
#   8. a named volume outlives its containers
#   9. ufw (if installed): route rules for every bridge, removed with
#      their network
#  10. a daemon restart: the containers, their ports and DNS still work
#  11. build: examples/hits as smoke-hits (pulls python:3-slim, RUN pip
#      install with the network), its image runs; built again, from the
#      cache
#  12. compose: examples/hits up -d (redis healthy before web starts), its
#      page counts visits through redis, ps shows web healthy, down -v
#      removes everything
#
# Everything it creates is named smoke-* (rlsmoke for the namespace and
# its veth) and removed at the end, also on failure.
set -uo pipefail

KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

R="sudo -n $PWD/target/debug/rustlet"
PORT=18080
PORT6=18086
IMG_WEB=nginx
IMG=alpine
FAILED=0

say()  { printf '\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '    ok: %s\n' "$*"; }
fail() { printf '\033[31m    FAILED: %s\033[0m\n' "$*"; FAILED=1; }
check() { # check DESCRIPTION COMMAND...
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$what"; else fail "$what"; fi
}

HOST_IP=$(ip -4 -o route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')
# A stable global (or unique local) IPv6 address of the host's, if it has one.
HOST_IP6=$(ip -6 -o addr show scope global 2>/dev/null | grep -v -e temporary -e deprecated | awk '{print $4}' | cut -d/ -f1 | head -1)
UFW="sudo -n systemd-run -q --pipe --wait /usr/sbin/ufw"

# A field of `rustlet network inspect`/`inspect`'s JSON (its first one).
field() { sed -n "s/.*\"$1\": \"\([^\"]*\)\".*/\1/p" | head -1; }
NETNS_EXISTED=0
[ -d /run/netns ] && NETNS_EXISTED=1

cleanup() {
  [ "$KEEP" = 1 ] && return
  say "cleanup"
  $R rm -f smoke-web smoke-db smoke-api smoke-web6 >/dev/null 2>&1
  $R network rm smoke-net smoke-net2 smoke-net6 >/dev/null 2>&1
  $R volume rm smoke-vol >/dev/null 2>&1
  $R compose -f examples/hits/compose.yaml -p smoke-hits down -v >/dev/null 2>&1
  $R rmi smoke-hits smoke-hits-web >/dev/null 2>&1
  sudo -n ip link del rlsmoke0 >/dev/null 2>&1
  sudo -n ip netns del rlsmoke >/dev/null 2>&1
  # `ip netns add` made /run/netns a mount point; leave the host as it was.
  if [ "$NETNS_EXISTED" = 0 ] && [ -d /run/netns ]; then
    sudo -n systemd-run -q --pipe --wait /usr/bin/umount /run/netns >/dev/null 2>&1
    sudo -n systemd-run -q --pipe --wait /usr/bin/rmdir /run/netns >/dev/null 2>&1
  fi
}
trap cleanup EXIT

say "0. the daemon"
$R version | sed 's/^/    /' || { echo "rustletd isn't answering"; exit 1; }
for i in $IMG $IMG_WEB; do
  $R images | grep -q "^docker.io/library/$i " || $R pull -q "$i" >/dev/null || fail "pull $i"
done

say "1. run"
out=$($R run --rm $IMG sh -c 'echo hello; exit 3'); code=$?
[ "$out" = hello ] && [ "$code" = 3 ] && ok "output and exit status 3" || fail "run said '$out', status $code"

say "2. a published port"
$R run -d --name smoke-web -p $PORT:80 $IMG_WEB >/dev/null || fail "run nginx"
for _ in $(seq 1 50); do curl -fs -o /dev/null http://127.0.0.1:$PORT/ && break; sleep 0.2; done
check "curl 127.0.0.1:$PORT (the proxy)" sh -c "curl -fsS http://127.0.0.1:$PORT/ | grep -q 'Welcome to nginx'"
check "curl $HOST_IP:$PORT (DNAT)" sh -c "curl -fsS http://$HOST_IP:$PORT/ | grep -q 'Welcome to nginx'"
WEB_IP=$($R inspect smoke-web | sed -n 's/.*"ip_address": "\([0-9.]*\)".*/\1/p' | head -1)
$R ps | grep -q "0.0.0.0:$PORT->80/tcp" && ok "ps shows 0.0.0.0:$PORT->80/tcp" || fail "ps doesn't show the port"

say "3. the LAN can't reach containers directly (container $WEB_IP)"
sudo -n ip netns add rlsmoke &&
  sudo -n ip link add rlsmoke0 type veth peer name lan0 netns rlsmoke &&
  sudo -n ip addr add 192.0.2.2/24 dev rlsmoke0 && sudo -n ip link set rlsmoke0 up &&
  sudo -n ip -6 addr add 2001:db8:5::2/64 dev rlsmoke0 nodad &&
  sudo -n ip netns exec rlsmoke ip addr add 192.0.2.1/24 dev lan0 &&
  sudo -n ip netns exec rlsmoke ip -6 addr add 2001:db8:5::1/64 dev lan0 nodad &&
  sudo -n ip netns exec rlsmoke ip link set lan0 up &&
  sudo -n ip netns exec rlsmoke ip link set lo up &&
  sudo -n ip netns exec rlsmoke ip route add 10.89.0.0/16 via 192.0.2.2 || fail "set up the LAN namespace"
check "the LAN reaches the published port" sudo -n ip netns exec rlsmoke curl -fsS -m 3 http://192.0.2.2:$PORT/
if sudo -n ip netns exec rlsmoke curl -fsS -m 3 "http://$WEB_IP/" >/dev/null 2>&1; then
  fail "the LAN reached $WEB_IP:80 directly"
else
  ok "the LAN can't reach $WEB_IP:80 directly"
fi

say "4. names on a user-defined network"
$R network create smoke-net >/dev/null || fail "network create"
$R run -d --name smoke-db --network smoke-net $IMG sleep 600 >/dev/null || fail "run smoke-db"
DB_IP=$($R inspect smoke-db | sed -n 's/.*"ip_address": "\([0-9.]*\)".*/\1/p' | head -1)
# getent: musl's resolver, as programs use it (busybox nslookup tries the
# search domains first, whatever ndots says).
out=$($R run --rm --network smoke-net $IMG getent hosts smoke-db 2>&1)
echo "$out" | grep -q "^$DB_IP " && ok "smoke-db is $DB_IP" || fail "getent hosts smoke-db: $out"
check "an outside name is forwarded" sh -c "$R run --rm --network smoke-net $IMG getent hosts deb.debian.org | grep -q ."

say "5. --ip, network connect and disconnect"
$R network create smoke-net2 >/dev/null || fail "network create smoke-net2"
NET1=$($R network inspect smoke-net | field subnet | sed 's/\.0\/24$//')
NET2=$($R network inspect smoke-net2 | field subnet | sed 's/\.0\/24$//')
$R run -d --name smoke-api --network smoke-net2 --ip "$NET2.50" $IMG sleep 600 >/dev/null || fail "run --ip $NET2.50"
[ "$($R inspect smoke-api | field ip_address)" = "$NET2.50" ] && ok "--ip: smoke-api is $NET2.50" || fail "smoke-api isn't $NET2.50"
$R network connect --alias api smoke-net smoke-api || fail "network connect smoke-net smoke-api"
check "smoke-api has eth1 now" $R exec smoke-api ip -o link show eth1
out=$($R run --rm --network smoke-net $IMG getent hosts api 2>&1)
echo "$out" | grep -q "^$NET1\." && ok "smoke-net answers its alias: $out" || fail "getent hosts api: $out"
$R network disconnect smoke-net smoke-api || fail "network disconnect smoke-net smoke-api"
out=$($R run --rm --network smoke-net $IMG sh -c 'getent hosts api || echo gone' 2>&1)
[ "$out" = gone ] && ok "disconnected: smoke-net has no api" || fail "after disconnect: $out"

say "6. an IPv6 network"
$R network create --ipv6 smoke-net6 >/dev/null || fail "network create --ipv6"
SUBNET6=$($R network inspect smoke-net6 | field subnet6)
[ -n "$SUBNET6" ] && ok "smoke-net6 has $SUBNET6" || fail "smoke-net6 has no IPv6 subnet"
check "IPv6 forwarding is on" sh -c "[ \$(cat /proc/sys/net/ipv6/conf/all/forwarding) = 1 ]"
$R run -d --name smoke-web6 --network smoke-net6 -p $PORT6:80 $IMG_WEB >/dev/null || fail "run smoke-web6"
WEB6=$($R inspect smoke-web6 | field ipv6_address)
for _ in $(seq 1 50); do curl -fs -o /dev/null -g "http://[::1]:$PORT6/" && break; sleep 0.2; done
check "curl [::1]:$PORT6 (the proxy, to $WEB6)" sh -c "curl -fsS -g 'http://[::1]:$PORT6/' | grep -q 'Welcome to nginx'"
if [ -n "$HOST_IP6" ]; then
  check "curl [$HOST_IP6]:$PORT6 (DNAT)" sh -c "curl -fsS -g 'http://[$HOST_IP6]:$PORT6/' | grep -q 'Welcome to nginx'"
fi
check "the LAN reaches it over IPv6 (DNAT, forwarded)" \
  sudo -n ip netns exec rlsmoke curl -fsS -m 3 -g "http://[2001:db8:5::2]:$PORT6/"
sudo -n ip netns exec rlsmoke ip -6 route add "$SUBNET6" via 2001:db8:5::2 || fail "route $SUBNET6 from the LAN"
if sudo -n ip netns exec rlsmoke curl -fsS -m 3 -g "http://[$WEB6]/" >/dev/null 2>&1; then
  fail "the LAN reached [$WEB6]:80 directly"
else
  ok "the LAN can't reach [$WEB6]:80 directly"
fi
out=$($R run --rm --network smoke-net6 $IMG getent ahostsv6 smoke-web6 2>&1 | head -1)
echo "$out" | grep -q "^$WEB6 " && ok "AAAA: smoke-web6 is $WEB6" || fail "getent ahostsv6 smoke-web6: $out"

say "7. --network container:smoke-web"
check "localhost is nginx's" sh -c "$R run --rm --network container:smoke-web $IMG wget -qO- http://127.0.0.1/ | grep -q 'Welcome to nginx'"

say "8. a named volume"
$R run --rm -v smoke-vol:/data $IMG sh -c 'echo persisted > /data/f' || fail "write to the volume"
out=$($R run --rm -v smoke-vol:/data $IMG cat /data/f)
[ "$out" = persisted ] && ok "the next container reads it" || fail "the volume held '$out'"

say "9. ufw"
if [ -x /usr/sbin/ufw ]; then
  added=$($UFW show added)
  status=$($UFW status | head -1)
  for net in bridge smoke-net smoke-net6; do
    b=$($R network inspect $net | field bridge)
    if echo "$added" | grep -qx "ufw route allow in on $b" && echo "$added" | grep -qx "ufw route allow out on $b"; then
      ok "ufw routes $b's traffic ($status)"
    else
      fail "ufw has no route rules for $b ($net)"
    fi
  done
  B2=$($R network inspect smoke-net2 | field bridge)
  $R rm -f smoke-api >/dev/null && $R network rm smoke-net2 >/dev/null || fail "remove smoke-net2"
  if $UFW show added | grep -q " on $B2\$"; then fail "ufw kept $B2's rules"; else ok "removing smoke-net2 removed $B2's rules"; fi
else
  ok "ufw isn't installed: nothing to check"
fi

say "10. a daemon restart"
sudo -n systemctl restart rustletd || fail "restart rustletd"
for _ in $(seq 1 50); do $R version >/dev/null 2>&1 && break; sleep 0.2; done
check "smoke-web is still running" sh -c "$R ps | grep -q smoke-web"
for _ in $(seq 1 50); do curl -fs -o /dev/null http://127.0.0.1:$PORT/ && break; sleep 0.2; done
check "its port answers on 127.0.0.1 again" curl -fsS http://127.0.0.1:$PORT/
check "and through DNAT" curl -fsS http://$HOST_IP:$PORT/
out=$($R run --rm --network smoke-net $IMG getent hosts smoke-db 2>&1)
echo "$out" | grep -q "^$DB_IP " && ok "names still resolve" || fail "after the restart: $out"
for _ in $(seq 1 50); do curl -fs -o /dev/null -g "http://[::1]:$PORT6/" && break; sleep 0.2; done
check "smoke-web6's port answers on [::1] again" curl -fsS -g "http://[::1]:$PORT6/"
check "and from the LAN over IPv6" sudo -n ip netns exec rlsmoke curl -fsS -m 3 -g "http://[2001:db8:5::2]:$PORT6/"

say "11. build"
if $R build -t smoke-hits examples/hits >/tmp/smoke-build.$$ 2>&1; then
  ok "examples/hits built ($(grep -c '^Step ' /tmp/smoke-build.$$) steps)"
else
  fail "build examples/hits: $(tail -3 /tmp/smoke-build.$$)"
fi
check "its image has the redis client" $R run --rm smoke-hits python -c 'import redis'
$R build -t smoke-hits examples/hits >/tmp/smoke-build.$$ 2>&1
cached=$(grep -c 'Using cache' /tmp/smoke-build.$$)
[ "$cached" -ge 2 ] && ok "built again: $cached steps from the cache" || fail "built again: $cached steps from the cache"
rm -f /tmp/smoke-build.$$

say "12. compose"
C="$R compose -f examples/hits/compose.yaml -p smoke-hits"
$C up -d >/tmp/smoke-compose.$$ 2>&1 || fail "compose up: $(tail -3 /tmp/smoke-compose.$$)"
rm -f /tmp/smoke-compose.$$
# up -d returns once web has started; its healthcheck says when it serves.
for _ in $(seq 1 150); do $C ps | grep smoke-hits-web-1 | grep -q '(healthy)' && break; sleep 0.2; done
check "compose ps shows web healthy" sh -c "$C ps | grep smoke-hits-web-1 | grep -q '(healthy)'"
first=$(curl -fsS http://127.0.0.1:8000/ 2>&1)
second=$(curl -fsS http://127.0.0.1:8000/ 2>&1)
echo "$first" | grep -q 'seen 1 times' && echo "$second" | grep -q 'seen 2 times' \
  && ok "the page counts through redis" || fail "the page said '$first' then '$second'"
$C down -v >/dev/null 2>&1 || fail "compose down"
check "down removed the containers" sh -c "! $R ps -a | grep -q smoke-hits-"
check "and the network" sh -c "! $R network ls | grep -q smoke-hits_default"
check "and the volume (-v)" sh -c "! $R volume ls | grep -q smoke-hits_data"

if [ "$FAILED" = 0 ]; then say "all checks passed"; else say "SOME CHECKS FAILED"; fi
exit "$FAILED"
