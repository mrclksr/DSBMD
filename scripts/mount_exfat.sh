#!/bin/sh
#
# mount_exfat - Mount an ExFAT device for reading and writing.
#
/usr/local/sbin/mount.exfat -o "uid=${DSBMD_UID},gid=${DSBMD_GID}" \
	${DSBMD_DEVICE} ${DSBMD_MNTPT} || exit 1
exit 0

