#!/usr/bin/env bash
# scripts/cleanup.sh: one-command host restore for Rustlets development.
#
# Removes every host resource Rustlets can create (they are all prefixed so
# they are easy to find; see docs/architecture.md §3 and §4):
#
#   1. stop rustletd
#   2. kill shims
#   3. cgroup.kill every container cgroup, wait for `populated 0`, rmdir deepest-first
#   4. unmount everything under /var/lib/rustlet and /run/rustlet, deepest-first
#   5. delete netns pins, the rustlet0 bridge and rlv* veths
#   6. nft delete table inet rustlet
#   7. restore ip_forward and the other host sysctls the daemon changed
#
# Usage: sudo scripts/cleanup.sh [--purge] [--dry-run]
#   --purge    also delete /var/lib/rustlet (images, volumes, state) and the
#              dev-storage loop image, plus the NetworkManager drop-in
#   --dry-run  print what would be done
set -uo pipefail

PURGE=0
DRY=0
for a in "$@"; do
  case "$a" in
    --purge) PURGE=1 ;;
    --dry-run) DRY=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" != 0 ] && [ "$DRY" = 0 ]; then
  exec sudo "$0" "$@"
fi

DATA=/var/lib/rustlet
RUN=/run/rustlet
CG=/sys/fs/cgroup
SYSCTL_ORIG="$RUN/host-sysctl.orig"
DEV_IMG=/var/lib/rustlet-dev-storage.img

run() {
  if [ "$DRY" = 1 ]; then echo "would: $*"; else "$@"; fi
}
say() { printf '\033[1m==> %s\033[0m\n' "$*"; }

# Read the recorded sysctls first; /run/rustlet is removed below.
SAVED_SYSCTLS=""
[ -f "$SYSCTL_ORIG" ] && SAVED_SYSCTLS="$(cat "$SYSCTL_ORIG")"

say "1. stopping rustletd"
if systemctl list-unit-files rustletd.service >/dev/null 2>&1 && systemctl is-active --quiet rustletd; then
  run systemctl stop rustletd
fi
if pgrep -x rustletd >/dev/null 2>&1; then run pkill -x rustletd && echo "   killed stray rustletd"; fi

say "2. killing shims"
run pkill -KILL -x rustlet-shim || true

say "3. killing and removing container cgroups"
# Containers live under the daemon's delegated subtree; test runs create
# `rustlet-*` cgroups inside systemd-run scopes.
mapfile -t CGDIRS < <( {
  [ -d "$CG/system.slice/rustletd.service" ] && find "$CG/system.slice/rustletd.service" -mindepth 1 -type d
  # ...and everything below them (container cgroups inside a test scope).
  find "$CG" -type d -name 'rustlet-*' -prune 2>/dev/null | while read -r d; do find "$d" -type d; done
} | awk '{ print gsub("/","/") " " $0 }' | sort -rn | cut -d' ' -f2- | uniq)
for d in "${CGDIRS[@]}"; do
  [ -d "$d" ] || continue
  if [ -f "$d/cgroup.kill" ]; then run sh -c "echo 1 > '$d/cgroup.kill'" 2>/dev/null; fi
done
for d in "${CGDIRS[@]}"; do
  [ -d "$d" ] || continue
  for _ in $(seq 1 50); do
    grep -q '^populated 0' "$d/cgroup.events" 2>/dev/null && break
    [ "$DRY" = 1 ] && break
    sleep 0.1
  done
  # systemd may remove an emptied scope's cgroup itself; only complain if it's still there.
  run rmdir "$d" 2>/dev/null || { [ -d "$d" ] && echo "   could not remove $d (still populated?)"; }
done

say "4. unmounting under $DATA and $RUN (deepest first)"
unmount_under() {
  local base="$1" self="$2"
  # field 5 of mountinfo is the mount point; octal-escaped spaces are decoded by printf %b
  awk -v b="$base" '{ mp=$5; if (mp == b || index(mp, b "/") == 1) print mp }' /proc/self/mountinfo |
    while read -r mp; do printf '%b\n' "$mp"; done |
    awk '{ print gsub("/","/") " " $0 }' | sort -rn | cut -d' ' -f2- |
    while read -r mp; do
      if [ "$mp" = "$base" ] && [ "$self" = 0 ]; then continue; fi
      run umount -l "$mp" && echo "   unmounted $mp"
    done
}
unmount_under "$RUN" 1
# Keep the dev-storage filesystem mounted at $DATA itself unless purging.
unmount_under "$DATA" "$PURGE"

say "5. removing netns pins and network links"
[ -d "$RUN/netns" ] && run find "$RUN/netns" -mindepth 1 -maxdepth 1 -type f -delete
for l in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^(rustlet[0-9]*|rlv[0-9a-f]+|rlb-.*)$'); do
  run ip link delete "$l" && echo "   deleted link $l"
done

say "6. removing nftables table inet rustlet"
if nft list table inet rustlet >/dev/null 2>&1; then run nft delete table inet rustlet; fi

say "7. restoring host sysctls"
if [ -n "$SAVED_SYSCTLS" ]; then
  while IFS='=' read -r k v; do
    [ -n "$k" ] || continue
    run sysctl -q -w "$k=$v" && echo "   $k = $v"
  done <<< "$SAVED_SYSCTLS"
else
  echo "   nothing recorded (ip_forward is $(cat /proc/sys/net/ipv4/ip_forward))"
fi

say "cleanup of $RUN"
[ -d "$RUN" ] && run rm -rf --one-file-system "$RUN"

if [ "$PURGE" = 1 ]; then
  say "purge: deleting $DATA and dev storage"
  if mountpoint -q "$DATA"; then run umount -l "$DATA"; fi
  if [ -f "$DEV_IMG" ]; then
    for loopdev in $(losetup -j "$DEV_IMG" -O NAME -n 2>/dev/null); do run losetup -d "$loopdev"; done
    run rm -f "$DEV_IMG"
  fi
  # Refuse if anything is still mounted below $DATA (never rm through a bind mount).
  if awk -v b="$DATA" 'index($5, b) == 1 { found=1 } END { exit !found }' /proc/self/mountinfo; then
    echo "   mounts still present under $DATA; not deleting it" >&2
  else
    [ -d "$DATA" ] && run rm -rf --one-file-system "$DATA"
  fi
  [ -f /etc/NetworkManager/conf.d/rustlet.conf ] && run rm -f /etc/NetworkManager/conf.d/rustlet.conf
fi

say "leftover check"
# Without root, `nft list` fails and some cgroups are unreadable, so absence proves nothing.
[ "$(id -u)" != 0 ] && echo "   (not root: the nft and cgroup checks below may miss leftovers; use sudo for a full answer)"
left=0
if grep -qE " ($DATA|$RUN)/" /proc/self/mountinfo; then echo "   mounts:";  grep -E " ($DATA|$RUN)/" /proc/self/mountinfo | awk '{print "     " $5}'; left=1; fi
if ip -o link show 2>/dev/null | grep -qE ': (rustlet|rlv)'; then echo "   links remain"; left=1; fi
if nft list table inet rustlet >/dev/null 2>&1; then echo "   nft table remains"; left=1; fi
if [ -d "$CG/system.slice/rustletd.service/containers" ] && [ -n "$(ls -A "$CG/system.slice/rustletd.service/containers" 2>/dev/null)" ]; then
  echo "   container cgroups remain"; left=1
fi
[ "$left" = 0 ] && echo "   host is clean"
exit "$left"
