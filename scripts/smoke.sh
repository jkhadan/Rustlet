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
#      `rlsmoke` plays a LAN host behind a veth (192.0.2.0/24, TEST-NET-1)
#      with a route to 10.89.0.0/16 through this host; the published port
#      answers it, the container's own address doesn't
#   4. names between containers on a user-defined network
#   5. --network container:X shares X's localhost
#   6. a named volume outlives its containers
#   7. a daemon restart: the container, its port and its DNS still work
#
# Everything it creates is named smoke-* (rlsmoke for the namespace and
# its veth) and removed at the end, also on failure.
set -uo pipefail

KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

R="sudo -n $PWD/target/debug/rustlet"
PORT=18080
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
NETNS_EXISTED=0
[ -d /run/netns ] && NETNS_EXISTED=1

cleanup() {
  [ "$KEEP" = 1 ] && return
  say "cleanup"
  $R rm -f smoke-web smoke-db >/dev/null 2>&1
  $R network rm smoke-net >/dev/null 2>&1
  $R volume rm smoke-vol >/dev/null 2>&1
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
  sudo -n ip netns exec rlsmoke ip addr add 192.0.2.1/24 dev lan0 &&
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

say "5. --network container:smoke-web"
check "localhost is nginx's" sh -c "$R run --rm --network container:smoke-web $IMG wget -qO- http://127.0.0.1/ | grep -q 'Welcome to nginx'"

say "6. a named volume"
$R run --rm -v smoke-vol:/data $IMG sh -c 'echo persisted > /data/f' || fail "write to the volume"
out=$($R run --rm -v smoke-vol:/data $IMG cat /data/f)
[ "$out" = persisted ] && ok "the next container reads it" || fail "the volume held '$out'"

say "7. a daemon restart"
sudo -n systemctl restart rustletd || fail "restart rustletd"
for _ in $(seq 1 50); do $R version >/dev/null 2>&1 && break; sleep 0.2; done
check "smoke-web is still running" sh -c "$R ps | grep -q smoke-web"
for _ in $(seq 1 50); do curl -fs -o /dev/null http://127.0.0.1:$PORT/ && break; sleep 0.2; done
check "its port answers on 127.0.0.1 again" curl -fsS http://127.0.0.1:$PORT/
check "and through DNAT" curl -fsS http://$HOST_IP:$PORT/
out=$($R run --rm --network smoke-net $IMG getent hosts smoke-db 2>&1)
echo "$out" | grep -q "^$DB_IP " && ok "names still resolve" || fail "after the restart: $out"

if [ "$FAILED" = 0 ]; then say "all checks passed"; else say "SOME CHECKS FAILED"; fi
exit "$FAILED"
