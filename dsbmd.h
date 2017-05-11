/*-
 * Copyright (c) 2016 Marcel Kaiser. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _DSBMD_H_
#define _DSBMD_H_

#include <pthread.h>
#include <stdbool.h>
#include "fs.h"

/*
 * Environment variables for external mount commands.
 */
#define ENV_UID			"DSBMD_UID"
#define ENV_GID			"DSBMD_GID"
#define ENV_DEV			"DSBMD_DEVICE"
#define ENV_LABEL		"DSBMD_LABEL"
#define ENV_FILESYSTEM		"DSBMD_FILESYSTEM"
#define ENV_MNTPT		"DSBMD_MNTPT"

#define NGLBLPRFX		5
#define GLBLPRFX		{ NULL, "label", "ufs", "ufsid", "gptid" }

#define PATH_DEVD_SOCKET	"/var/run/devd.pipe"

#define SOCKET_MODE		(S_IRWXU | S_IRWXG | S_IRWXO)

#define PATH_TMP_MNT_TEMPLATE	"/tmp/mnt.XXXXXX"

#define CMD_MOUNT		'M'
#define CMD_UNMOUNT		'U'
#define MSG_DSBMD_SHUTDOWN	'S'
#define CMD_EJECT		'E'
#define CMD_SPEED		'V'

#define ERR_ALREADY_MOUNTED	((1 << 8) + 0x01)
#define ERR_PERMISSION_DENIED	((1 << 8) + 0x02)
#define ERR_NOT_MOUNTED		((1 << 8) + 0x03)
#define ERR_DEVICE_BUSY		((1 << 8) + 0x04)
#define ERR_NO_SUCH_DEVICE	((1 << 8) + 0x05)
#define ERR_MAX_CONN_REACHED	((1 << 8) + 0x06)
#define ERR_NOT_EJECTABLE	((1 << 8) + 0x07)
#define ERR_UNKNOWN_COMMAND	((1 << 8) + 0x08)
#define ERR_UNKNOWN_OPTION	((1 << 8) + 0x09)
#define ERR_SYNTAX_ERROR	((1 << 8) + 0x0a)
#define ERR_NO_MEDIA		((1 << 8) + 0x0b)
#define ERR_UNKNOWN_FILESYSTEM	((1 << 8) + 0x0c)
#define ERR_UNKNOWN_ERROR	((1 << 8) + 0x0d)
#define ERR_MNTCMD_FAILED	((1 << 8) + 0x0e)
#define ERR_INVALID_ARGUMENT	((1 << 8) + 0x0f)
#define ERR_STRING_TOO_LONG	((1 << 8) + 0x10)
#define ERR_BAD_STRING		((1 << 8) + 0x11)

/*
 * Devices to look for
 */
typedef struct dskcl_s {
	char system;
#define ATA	0x00
#define CAM 	0x01
#define MMC	0x02
#define USB	0x03
#define OTHER	0xff
	char class;
#define CDROM 	0x00
#define MSD	0x01			 /* Mass storage devices */
#define FLOPPY	0x02
#define MD	0x03			 /* Memory disk */
#define FUSE	0x04
#define LLV	0x05
#define MTP	0x06
	const char *pattern;		 /* ad, da, cd ... */
} dskcl_t;

enum DSK_TYPES {
	CDR_TYPE_RAW,	CDR_TYPE_VCD,  CDR_TYPE_SVCD,	 CDR_TYPE_DVD,
	CDR_TYPE_AUDIO, CDR_TYPE_DATA, CDR_TYPE_UNKNOWN, DSK_TYPE_USBDISK,
	DSK_TYPE_HDD,	DSK_TYPE_FLOPPY, DSK_TYPE_MMC, DSK_TYPE_FUSE,
	DSK_TYPE_MTP
};

/*
 * Struct to identify disks. E.g., VCD, DVD, AUDIO CD, etc.
 */
typedef struct dsktype_s {
	int   dt_type;			 /* Numeric disk type ID. */
	char *dt_name;			 /* Disk type string. */
} dsktp_t;

/*
 * Struct to manage disks found on the system
 */
typedef struct drive_s {
	int		speed;
	bool		mounted;
	bool		has_media;
	bool		polling;	  /* May be polled. */
	char		*realdev;	  /* Actual device in case of a LV */
	char		*name;		  /* Volume ID */
	char		*model;		  /* "<vendor> <product> <revision>" */
	char		*glabel[NGLBLPRFX];/* GEOM labels. */
	char		*dev;		  /* Path to special file */
	char		*mntpt;		  /* Mountpoint */
	fs_t		*fs;		  /* Filesystem type */
	const dsktp_t	*dt;		  /* Disk type */
	const dskcl_t	*dc;		  /* Disk class */
	pthread_mutex_t mtx;
} drive_t;

/*
 * Struct to manage clients.
 */
typedef struct client_s {
	FILE  *s;			  /* Client socket. */
	uid_t uid;			  /* Client UID. */
	gid_t *gids;			  /* Client GIDs. */
	pthread_mutex_t mtx;		  /* Mutex to synchronize messages. */
} client_t;

#endif	/* !_DSBMD_H_ */
