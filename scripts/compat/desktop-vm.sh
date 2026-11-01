#!/usr/bin/env bash
# A disposable desktop VM for the packaged-app tests (docs/client-compatibility.md
# "Full desktop VMs"): a pinned distribution image booted under KVM on the CI
# runner, provisioned with cloud-init into a real Xfce session that logs in by
# itself. The compat harness stays on the runner (panel, engines, the
# subscription it serves on 127.0.0.1:4179); only the application runs in the
# VM, inside that session (scripts/compat/sfl-remote.sh).
#
#   desktop-vm.sh up <target>   boot and provision; returns once Xfce runs
#   desktop-vm.sh install-sfl   install the verified SFL .deb the way a user does
#   desktop-vm.sh ssh <cmd>     run a command in the VM
#   desktop-vm.sh down          stop the VM (the disk is thrown away)
#
# QEMU runs from a digest-pinned image, so the runner needs Docker and /dev/kvm
# and nothing from its own (sometimes stalling) package mirror.
set -euo pipefail

QEMU_IMAGE='tianon/qemu:11.0.5-native-trixie@sha256:bc90922dfbeb8d16907e16f0520730cf3b3998de2faf402cbaba4011abad7840'
VM_DIR="$PWD/.cache/compat/vm"
SSH_PORT=2222
SEED_PORT=8123
CONTAINER=fcp-compat-desktop-vm
USER_NAME=fcp

# Pinned images. Bump the build date and its SHA-512 together, from the
# build's own SHA512SUMS.
image_for() {
  case "$1" in
    debian-13-xfce)
      IMAGE_URL='https://cloud.debian.org/images/cloud/trixie/20261017-2634/debian-13-generic-amd64-20261017-2634.qcow2'
      IMAGE_SHA512='62aa92aeff32cbf3fe6c01f410fef4035b1603a512f073c9f8889072168de9e49fa361ba48621359fc7608ad91225e823ea233feb33f612eb39e50aaf21957fe'
      ;;
    *)
      echo "unknown desktop target: $1" >&2
      exit 2
      ;;
  esac
}

# VM_SSH_OPTS: extra ssh options (a port forward), word-split on purpose.
vm_ssh() {
  # shellcheck disable=SC2086
  ssh -i "$VM_DIR/id_ed25519" -p "$SSH_PORT" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    -o ConnectTimeout=5 -o ServerAliveInterval=15 ${VM_SSH_OPTS:-} \
    "$USER_NAME@127.0.0.1" "$@"
}

wait_for() { # wait_for <seconds> <what> <command...>
  local deadline=$((SECONDS + $1)) what=$2
  shift 2
  until "$@" >/dev/null 2>&1; do
    if ((SECONDS > deadline)); then
      echo "timed out waiting for $what" >&2
      tail -n 40 "$VM_DIR/serial.log" >&2 || true
      return 1
    fi
    sleep 5
  done
}

up() {
  local target=$1
  image_for "$target"
  test -r /dev/kvm && test -w /dev/kvm || {
    echo "this runner has no usable /dev/kvm" >&2
    exit 1
  }
  mkdir -p "$VM_DIR/seed"
  local base
  base="$VM_DIR/$(basename "$IMAGE_URL")"
  if ! echo "$IMAGE_SHA512  $base" | sha512sum -c --status 2>/dev/null; then
    curl -fsSL --retry 3 -o "$base.part" "$IMAGE_URL"
    echo "$IMAGE_SHA512  $base.part" | sha512sum -c --status
    mv "$base.part" "$base"
  fi
  rm -f "$VM_DIR/disk.qcow2" "$VM_DIR/id_ed25519" "$VM_DIR/id_ed25519.pub" "$VM_DIR/serial.log"
  ssh-keygen -q -t ed25519 -N '' -C fcp-compat-vm -f "$VM_DIR/id_ed25519"

  # NoCloud over HTTP: QEMU's user network maps 10.0.2.2 to the runner's
  # loopback, where this seed server answers cloud-init.
  cat >"$VM_DIR/seed/meta-data" <<EOF
instance-id: fcp-$target-$(date +%s)
local-hostname: fcp-$target
EOF
  cat >"$VM_DIR/seed/user-data" <<EOF
#cloud-config
users:
  - name: $USER_NAME
    groups: [sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys: ['$(cat "$VM_DIR/id_ed25519.pub")']
package_update: true
# A desktop as a member installs it: Xfce under LightDM on Xorg, with the
# packages' own recommendations. nodejs runs the app driver.
packages: [xfce4, lightdm, xserver-xorg, dbus-x11, nodejs]
write_files:
  - path: /etc/lightdm/lightdm.conf.d/50-fcp-autologin.conf
    defer: true
    content: |
      [Seat:*]
      autologin-user=$USER_NAME
      autologin-session=xfce
runcmd:
  - [systemctl, set-default, graphical.target]
  - [systemctl, restart, lightdm]
EOF
  (cd "$VM_DIR/seed" && exec python3 -m http.server "$SEED_PORT" --bind 127.0.0.1) \
    >/dev/null 2>&1 &
  echo $! >"$VM_DIR/seed.pid"

  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker run --rm --network host --entrypoint qemu-img -v "$VM_DIR:/vm" "$QEMU_IMAGE" \
    create -q -f qcow2 -F qcow2 -b "/vm/$(basename "$base")" /vm/disk.qcow2 24G
  # Half the runner: the panel, the engines and the harness keep the rest.
  docker run -d --name "$CONTAINER" --network host --device /dev/kvm \
    -v "$VM_DIR:/vm" --entrypoint qemu-system-x86_64 "$QEMU_IMAGE" \
    -enable-kvm -cpu host -smp 2 -m 6144 \
    -drive file=/vm/disk.qcow2,if=virtio,cache=unsafe,discard=unmap \
    -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" \
    -smbios "type=1,serial=ds=nocloud;s=http://10.0.2.2:$SEED_PORT/" \
    -vga std -display none -vnc 127.0.0.1:0 \
    -serial file:/vm/serial.log >/dev/null

  wait_for 300 'SSH in the VM' vm_ssh true
  # Package installation is the long part (a few minutes on a hosted runner).
  vm_ssh 'cloud-init status --wait >/dev/null; cloud-init status --format json' |
    python3 -c 'import json,sys; s=json.load(sys.stdin); sys.exit(0 if s["status"]=="done" and not s.get("errors") else 1)' || {
    echo "cloud-init did not finish cleanly" >&2
    vm_ssh 'sudo tail -n 60 /var/log/cloud-init-output.log' >&2 || true
    exit 1
  }
  wait_for 180 'the Xfce session' vm_ssh "pgrep -u $USER_NAME -x xfce4-session"
  kill "$(cat "$VM_DIR/seed.pid")" 2>/dev/null || true
  vm_ssh '. /etc/os-release; echo "VM: $PRETTY_NAME, kernel $(uname -r)"'
}

install_sfl() {
  # The checksum-verified package from scripts/compat/download.ts, installed
  # with apt like a member would: its postinst enables and starts the daemon.
  vm_ssh 'cat > /tmp/sfl.deb' <.cache/compat/bin/sfl.deb
  vm_ssh 'sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q /tmp/sfl.deb >/dev/null && rm /tmp/sfl.deb'
  wait_for 60 'the sing-box daemon socket' vm_ssh 'test -S /run/sing-box.socket'

  # The driver (tests/compat/sfl.ts) and the packages it loads, laid out as in
  # the repository so its relative paths hold.
  local stage="$VM_DIR/stage"
  rm -rf "$stage"
  mkdir -p "$stage/.cache/compat/runtime" "$stage/node_modules"
  bun --no-env-file build tests/compat/sfl.ts --target=node --packages=external \
    --outfile "$stage/.cache/compat/runtime/sfl.mjs" >/dev/null
  cp .cache/compat/resolved-artifacts.json "$stage/.cache/compat/"
  for pkg in @playwright/test playwright playwright-core yaml; do
    mkdir -p "$stage/node_modules/$(dirname "$pkg")"
    cp -R "node_modules/$pkg" "$stage/node_modules/$pkg"
  done
  vm_ssh 'rm -rf ~/fcp && mkdir ~/fcp'
  tar -C "$stage" -cf - . | vm_ssh 'tar -C ~/fcp -xf -'
}

down() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  if [ -f "$VM_DIR/seed.pid" ]; then kill "$(cat "$VM_DIR/seed.pid")" 2>/dev/null || true; fi
  rm -f "$VM_DIR/disk.qcow2" "$VM_DIR/seed.pid"
}

case "${1:-}" in
  up) up "${2:?target}" ;;
  install-sfl) install_sfl ;;
  ssh)
    shift
    vm_ssh "$@"
    ;;
  down) down ;;
  *)
    echo "usage: $0 up <target> | install-sfl | ssh <command> | down" >&2
    exit 2
    ;;
esac
