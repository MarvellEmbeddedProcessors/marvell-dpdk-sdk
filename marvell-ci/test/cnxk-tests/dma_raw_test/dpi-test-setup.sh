#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2026 Marvell.

# Bind Marvell DPI VFs + NPA PF to vfio-pci and allocate hugepages.
# If called with 'unbind', undo the steps (rebind default drivers, remove VFs, cleanup hugepages).

set -euo pipefail

# ----------------------------- Config ---------------------------------
NUM_DPI=1                   # Number of DPI PFs to use (e.g., 1 or 2 on 98xx)
NUMVFS=12                   # Number of VFs to create per DPI PF (fixed)
HUGEPG_SZ_KB=524288         # 512MB hugepages (524288 kB)
HUGEPG_COUNT=12             # Number of 512MB hugepages to allocate (fixed)
HUGEPG_MNT=/dev/huge        # HugeTLB mountpoint for DPDK

# PCI IDs (Marvell CNXK/CN10K family examples)
DPI_PF_ID="177d:a080"
DPI_VF_ID="177d:a081"
NPA_PF_ID="177d:a0fb"

# State file to record original drivers (optional; restore also works without it)
STATE_FILE="/var/run/dpi_vfio_bind.state"

# ----------------------------- Helpers --------------------------------
msg() { echo -e "[*] $*"; }
err() { echo -e "[!] $*" >&2; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root."
    exit 1
  fi
}

mounted_hugetlbfs() {
  mountpoint -q "$HUGEPG_MNT" && grep -q " $HUGEPG_MNT " /proc/mounts | grep -q hugetlbfs
}

get_current_driver() {
  local bdf="$1"
  if [[ -L "/sys/bus/pci/devices/$bdf/driver" ]]; then
    basename "$(readlink -f "/sys/bus/pci/devices/$bdf/driver")"
  else
    echo "none"
  fi
}

bind_to_vfio() {
  local bdf="$1"
  local curdrv
  curdrv="$(get_current_driver "$bdf")"

  # Save original driver mapping
  echo "$bdf,$curdrv" >> "$STATE_FILE"

  if [[ "$curdrv" != "vfio-pci" && -e "/sys/bus/pci/devices/$bdf/driver/unbind" ]]; then
    echo "$bdf" > "/sys/bus/pci/devices/$bdf/driver/unbind" || true
  fi

  echo vfio-pci > "/sys/bus/pci/devices/$bdf/driver_override"
  echo "$bdf" > /sys/bus/pci/drivers_probe

  local nowdrv
  nowdrv="$(get_current_driver "$bdf")"
  if [[ "$nowdrv" != "vfio-pci" ]]; then
    err "Failed to move $bdf to vfio-pci (now: $nowdrv)"
    exit 1
  fi
  msg "Device $bdf moved to vfio-pci (was: $curdrv)"
}

restore_from_vfio() {
  local bdf="$1"

  # Clear override first so default matching can occur
  if [[ -w "/sys/bus/pci/devices/$bdf/driver_override" ]]; then
    : > "/sys/bus/pci/devices/$bdf/driver_override" || true
  fi

  # If currently bound to vfio-pci, unbind
  if [[ -e "/sys/bus/pci/drivers/vfio-pci/unbind" ]]; then
    if [[ "$(get_current_driver "$bdf")" == "vfio-pci" ]]; then
      echo "$bdf" > /sys/bus/pci/drivers/vfio-pci/unbind || true
    fi
  fi

  # Re-probe so the default kernel driver (matching the PCI ID) attaches
  echo "$bdf" > /sys/bus/pci/drivers_probe || true

  msg "Device $bdf restored to kernel driver: $(get_current_driver "$bdf")"
}

# ----------------------------- Discovery ------------------------------
get_dpipf_list() {
  # DPI PFs
  lspci -Dnnd "$DPI_PF_ID" | awk '{print $1}' | head -"$NUM_DPI"
}

get_dpivf_list() {
  # All DPI VFs
  lspci -Dnnd "$DPI_VF_ID" | awk '{print $1}'
}

get_npapf() {
  lspci -Dnnd "$NPA_PF_ID" | awk '{print $1}' | head -1
}

# ----------------------------- Actions --------------------------------
hugepages_setup() {
  msg "Mounting hugetlbfs and allocating hugepages..."
  mkdir -p "$HUGEPG_MNT"
  if ! mounted_hugetlbfs; then
    mount -t hugetlbfs nodev "$HUGEPG_MNT"
  fi
  local hp_sys="/sys/kernel/mm/hugepages/hugepages-${HUGEPG_SZ_KB}kB/nr_hugepages"
  if [[ -w "$hp_sys" ]]; then
    echo "$HUGEPG_COUNT" > "$hp_sys"
    msg "Set ${HUGEPG_COUNT} hugepages of size ${HUGEPG_SZ_KB}kB"
  else
    err "Hugepage size ${HUGEPG_SZ_KB}kB not supported on this kernel."
    exit 1
  fi
}

hugepages_teardown() {
  msg "Releasing hugepages and unmounting hugetlbfs..."
  local hp_sys="/sys/kernel/mm/hugepages/hugepages-${HUGEPG_SZ_KB}kB/nr_hugepages"
  if [[ -w "$hp_sys" ]]; then
    echo 0 > "$hp_sys" || true
  fi
  if mounted_hugetlbfs; then
    umount "$HUGEPG_MNT" || true
  fi
}

create_dpi_vfs() {
  local pf_list="$1"
  local pf
  for pf in $pf_list; do
    local cur="$(cat /sys/bus/pci/devices/$pf/sriov_numvfs)"
    msg "Current number of VFs under DPI PF $pf = $cur"
    if [[ "$cur" != "$NUMVFS" ]]; then
      local total="$(cat /sys/bus/pci/devices/$pf/sriov_totalvfs)"
      local want="$NUMVFS"
      if (( total < NUMVFS )); then
        want="$total"
      fi
      msg "Creating $want VFs for DPI PF $pf ..."
      echo 0 > "/sys/bus/pci/devices/$pf/sriov_numvfs"
      echo "$want" > "/sys/bus/pci/devices/$pf/sriov_numvfs"
      if [[ $? -ne 0 ]]; then
        err "Failed to enable VFs for $pf"
        exit 1
      fi
    fi
  done
}

destroy_dpi_vfs() {
  local pf_list="$1"
  local pf
  for pf in $pf_list; do
    if [[ -w "/sys/bus/pci/devices/$pf/sriov_numvfs" ]]; then
      msg "Removing VFs for DPI PF $pf ..."
      echo 0 > "/sys/bus/pci/devices/$pf/sriov_numvfs" || true
    fi
  done
}

bind_devices() {
  : > "$STATE_FILE"  # reset record
  local dpivf_list="$1"
  local npapf="$2"
  msg "###### DPI VFs ######"
  echo "$dpivf_list"
  msg "Using NPA PF $npapf ..."
  local dev
  for dev in $dpivf_list $npapf; do
    [[ -z "$dev" ]] && continue
    bind_to_vfio "$dev"
  done
  msg "Bindings recorded in $STATE_FILE"
}

restore_devices() {
  local dpivf_list="$1"
  local npapf="$2"

  local dev
  for dev in $dpivf_list $npapf; do
    [[ -z "$dev" ]] && continue
    restore_from_vfio "$dev"
  done

  if [[ -s "$STATE_FILE" ]]; then
    msg "Restoring any remaining devices from state file..."
    while IFS=, read -r bdf _; do
      [[ -z "$bdf" ]] && continue
      if [[ -e "/sys/bus/pci/devices/$bdf" ]]; then
        restore_from_vfio "$bdf"
      fi
    done < "$STATE_FILE"
    rm -f "$STATE_FILE" || true
  fi
}

# ----------------------------- Main -----------------------------------
require_root

ACTION="${1:-bind}"

DPIPF="$(get_dpipf_list)"
msg "###### DPI PFs ######"
[[ -n "$DPIPF" ]] && echo "$DPIPF" || err "No DPI PFs found matching $DPI_PF_ID"

case "$ACTION" in
  bind)
    hugepages_setup
    echo
    msg "Creating DPI VFs ..."
    create_dpi_vfs "$DPIPF"

    DPIVF="$(get_dpivf_list)"
    echo
    msg "###### DPI VFs ######"
    [[ -n "$DPIVF" ]] && echo "$DPIVF" || err "No DPI VFs found after creation"

    NPAPF="$(get_npapf)"
    echo
    msg "Using NPA PF $NPAPF ..."
    bind_devices "$DPIVF" "$NPAPF"
    ;;

  unbind)
    DPIVF="$(get_dpivf_list)"
    NPAPF="$(get_npapf)"

    restore_devices "$DPIVF" "$NPAPF"
    destroy_dpi_vfs "$DPIPF"
    hugepages_teardown

    msg "Unbind and cleanup complete."
    ;;

  *)
    err "Unknown action: $ACTION"
    echo "Usage: $0 [bind|unbind]"
    exit 2
    ;;

esac
