#!/bin/sh
#
# mount_ntfs - Mount a NTFS device for reading and writing.
#
/usr/local/bin/ntfs-3g -o "uid=${DSBMD_UID},gid=${DSBMD_GID}" \
	${DSBMD_DEVICE} ${DSBMD_MNTPT} || exit 1
exit 0

