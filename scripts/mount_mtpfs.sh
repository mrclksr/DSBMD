#!/bin/sh
#
# mount_mtpfs - Mount a MTP device using simple-mtpfs
#
/usr/local/bin/simple-mtpfs -o "uid=${DSBMD_UID},gid=${DSBMD_GID}" \
	${DSBMD_DEVICE} ${DSBMD_MNTPT} || exit 1
exit 0

