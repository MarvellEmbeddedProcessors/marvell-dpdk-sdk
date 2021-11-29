#!/bin/bash -x
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

# Script syntax:
# cnxk-target-setup.sh
#
# Optional environment variables:
# HP How many hugepages of default size to enable.
# DEVS Space separated list of PCI devices to bind to VFIO. By default bind
#      0002:01:00.1.
# VFIO_DEVBIND Alternative location of oxk-devbind-basic.sh script.
# TARGET_BOARD Optional SSH URL for the target board to setup. If not given,
#              all commands are run locally. If it is given the script is
#              copied to REMOTE_DIR on the TARGET_BOARD and run from there.
# PERF_STAGE Flag to bind PF devices used in perf stage to vfio.
#
# Below options are used only when TARGET_BOARD is set.
#
# TARGET_SSH_CMD ssh cmd used to connect to target. Default is "ssh"
# TARGET_SCP_CMD scp cmd used to connect to target. Default is "scp"
# REMOTE_DIR Directory where ODP build dir is located on the remote target.
#            It is used to find oxk-devbind-basic.sh script.
# SUDO This is used only when the command is to run as sudo on the
#      remote target. Default set to "sudo" i.e. to run as SUDO.
#
# Script will:
# 1. Mount hugetlbfs and enable HP hugepages of default size.
# 2. Bind each PCI device in DEVS using oxk-devbind-basic.sh.
# 3. Sets device configuration.

set -euo pipefail
shopt -s extglob

# Script arguments
SCRIPTPATH="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
SCRIPTNAME="$(basename $0)"
HP=${HP:-24}
PARTNUM_98XX=0x0b1
PARTNUM_96XX=0x0b2
DEVS=${DEVS:-0002:01:00.1 0002:01:00.2 0002:01:00.3}
PERF_STAGE=${PERF_STAGE:-}

if [ -n "${TARGET_BOARD:-}" ]; then
	SUDO=${SUDO:-"sudo"}
	TARGET_SSH_CMD=${TARGET_SSH_CMD:-"ssh"}
	TARGET_SCP_CMD=${TARGET_SCP_CMD:-"scp"}
	REMOTE_DIR=${REMOTE_DIR:-/tmp/dpdk}
	$TARGET_SSH_CMD $TARGET_BOARD mkdir -p $REMOTE_DIR
	$TARGET_SCP_CMD $SCRIPTPATH/$SCRIPTNAME $TARGET_BOARD:$REMOTE_DIR/cnxk-target-setup.sh
	VFIO_DEVBIND=${VFIO_DEVBIND:-$REMOTE_DIR/marvell-ci/test/board/oxk-devbind-basic.sh}
	TARGET_EXPORTS="VFIO_DEVBIND=$VFIO_DEVBIND PERF_STAGE=$PERF_STAGE"
	$TARGET_SSH_CMD $TARGET_BOARD \
		"$SUDO $TARGET_EXPORTS $REMOTE_DIR/cnxk-target-setup.sh"
	exit 0
else
	VFIO_DEVBIND=${VFIO_DEVBIND:-$(which oxk-devbind-basic.sh)}
fi

# Get CPU PART NUMBER
PARTNUM=$(grep -m 1 'CPU part' /proc/cpuinfo | grep -o '0x0[a-b][0-3]$')

# Mount hugetlbfs.
if [ -z "$(mount | grep hugepages 2>/dev/null)" ]; then
	mount -t hugetlbfs none /dev/hugepages/
fi
# Enable HP hugepages. There's a different case for local and remote to make it
# easier to read the actual command than a convoluted one-liner.
sh -c "echo $HP > /proc/sys/vm/nr_hugepages"

echo 24 > /sys/bus/pci/devices/0002\:10\:00.0/kvf_limits
# Disable existing VFs and enable CPT VFs
if [[ -e /sys/bus/pci/devices/0002\:10\:00.0/sriov_numvfs ]]; then
	sh -c "echo 0 > /sys/bus/pci/devices/0002\:10\:00.0/sriov_numvfs"
	sh -c "echo 2 > /sys/bus/pci/devices/0002\:10\:00.0/sriov_numvfs"
	DEVS+=(0002:10:00.1)
fi

# Bind SSO and NPA devices
SSO_DEV=${SSO_DEV:-$(lspci -d :a0f9 | tail -1 | awk -e '{ print $1 }')}
NPA_DEV=${NPA_DEV:-$(lspci -d :a0fb | tail -1 | awk -e '{ print $1 }')}

# Unbound all sso devices first
for d in $(lspci -d :a0f9 | awk -e '{ print $1 }'); do
	$VFIO_DEVBIND -u $d || exit 1
done

DEVS+=" $SSO_DEV"
DEVS+=" $NPA_DEV"

for d in ${DEVS[@]}; do
	$VFIO_DEVBIND -b vfio-pci $d || exit 1
done

set +euo pipefail

sh -c "echo 0 > /sys/bus/pci/devices/0002\:02\:00.0/limits/ssow"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:03\:00.0/limits/ssow"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:04\:00.0/limits/ssow"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:05\:00.0/limits/ssow"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:06\:00.0/limits/ssow"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:07\:00.0/limits/ssow"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:08\:00.0/limits/ssow"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:09\:00.0/limits/ssow"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:0a\:00.0/limits/ssow"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:0b\:00.0/limits/ssow"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:0c\:00.0/limits/ssow"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:0d\:00.0/limits/ssow"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:0e\:00.0/limits/ssow"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:0f\:00.0/limits/ssow"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:10\:00.0/limits/ssow"
if [[ $PARTNUM == $PARTNUM_98XX ]]; then
	sh -c "echo 0 > /sys/bus/pci/devices/0002\:11\:00.0/limits/ssow"
	sh -c "echo 0 > /sys/bus/pci/devices/0002\:12\:00.0/limits/ssow"
	sh -c "echo 0 > /sys/bus/pci/devices/0002\:13\:00.0/limits/ssow"
	sh -c "echo 0 > /sys/bus/pci/devices/0002\:14\:00.0/limits/ssow"
	sh -c "echo 0 > /sys/bus/pci/devices/0002\:15\:00.0/limits/ssow"
	sh -c "echo 0 > /sys/bus/pci/devices/0002\:16\:00.0/limits/ssow"
	sh -c "echo 0 > /sys/bus/pci/devices/0002\:17\:00.0/limits/ssow"
	sh -c "echo 0 > /sys/bus/pci/devices/0002\:18\:00.0/limits/ssow"
fi

sh -c "echo 0 > /sys/bus/pci/devices/0002\:02\:00.0/limits/sso"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:03\:00.0/limits/sso"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:04\:00.0/limits/sso"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:05\:00.0/limits/sso"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:06\:00.0/limits/sso"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:07\:00.0/limits/sso"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:08\:00.0/limits/sso"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:09\:00.0/limits/sso"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:0a\:00.0/limits/sso"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:0b\:00.0/limits/sso"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:0c\:00.0/limits/sso"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:0d\:00.0/limits/sso"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:0e\:00.0/limits/sso"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:0f\:00.0/limits/sso"
sh -c "echo 0 > /sys/bus/pci/devices/0002\:10\:00.0/limits/sso"
if [[ $PARTNUM == $PARTNUM_98XX ]]; then
	sh -c "echo 0 > /sys/bus/pci/devices/0002\:11\:00.0/limits/sso"
	sh -c "echo 0 > /sys/bus/pci/devices/0002\:12\:00.0/limits/sso"
	sh -c "echo 0 > /sys/bus/pci/devices/0002\:13\:00.0/limits/sso"
	sh -c "echo 0 > /sys/bus/pci/devices/0002\:14\:00.0/limits/sso"
	sh -c "echo 0 > /sys/bus/pci/devices/0002\:15\:00.0/limits/sso"
	sh -c "echo 0 > /sys/bus/pci/devices/0002\:16\:00.0/limits/sso"
	sh -c "echo 0 > /sys/bus/pci/devices/0002\:17\:00.0/limits/sso"
	sh -c "echo 0 > /sys/bus/pci/devices/0002\:18\:00.0/limits/sso"
fi

sh -c "echo 256 > /sys/bus/pci/devices/$SSO_DEV/limits/sso"
# Max number of available work slots are (2 x num_core) + 4.
# Max limit needs to be set for tests to run in dual workslot mode.
if [[ $PARTNUM == $PARTNUM_96XX ]]; then
	sh -c "echo 46 > /sys/bus/pci/devices/$SSO_DEV/limits/ssow"
elif [[ $PARTNUM == $PARTNUM_98XX ]]; then
	sh -c "echo 76 > /sys/bus/pci/devices/$SSO_DEV/limits/ssow"
fi

sh -c "echo 8 > /sys/bus/pci/devices/$SSO_DEV/limits/tim"

# test/validation/api/traffic_mngr_main needs more resources.
# Set 256 SMQ and TL4 for AFVF's and give remaining 256 to PF's
pktio_pf_list=$(lspci -d :a063 | cut -f 1 -d ' ')
count=$(echo $pktio_pf_list | wc -w)
per_pf=$(expr 256 / $count)

for d in $pktio_pf_list
do
	# Unbind before changing limits
	$VFIO_DEVBIND -u $d || exit 1
	sh -c "echo 0 > /sys/bus/pci/devices/$d/limits/smq"
	sh -c "echo 0 > /sys/bus/pci/devices/$d/limits/tl4"
done

for d in $pktio_pf_list
do
	sh -c "echo $per_pf > /sys/bus/pci/devices/$d/limits/smq"
	sh -c "echo $per_pf > /sys/bus/pci/devices/$d/limits/tl4"
done
sh -c "echo 256 > /sys/bus/pci/devices/0002:01:00.0/limits/smq"
sh -c "echo 256 > /sys/bus/pci/devices/0002:01:00.0/limits/tl4"

# Bind interfaces used in perf stage to vfio
if [[ $PERF_STAGE -eq 1 ]]; then
	perf_pf_list=(0002:02:00.0 0002:03:00.0)
	for pf in  ${perf_pf_list[@]}; do
		$VFIO_DEVBIND -b vfio-pci $pf || exit 1
	done
fi
set -euo pipefail
