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
#include <sys/queue.h>

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
#define ENV_USB_PORT		"DSBMD_GPHOTO_USB_PORT"

#define NGLBLPRFX		6
#define GLBLPRFX		{ NULL, "label", "ufs", "gpt", "ufsid", "gptid" }

#define PATH_DEVD_SOCKET	"/var/run/devd.seqpacket.pipe"

#define SOCK_ERR_CONN_CLOSED	1
#define SOCK_ERR_IO_ERROR	2

#define SOCKET_MODE		(S_IRWXU | S_IRWXG | S_IRWXO)

#define CMD_MOUNT		'M'
#define CMD_UNMOUNT		'U'
#define MSG_DSBMD_SHUTDOWN	'S'
#define CMD_EJECT		'E'
#define CMD_SPEED		'V'

enum {
	ERR_ALREADY_MOUNTED = 257, ERR_PERMISSION_DENIED, ERR_NOT_MOUNTED,
	ERR_DEVICE_BUSY, ERR_NO_SUCH_DEVICE, ERR_MAX_CONN_REACHED,
	ERR_NOT_EJECTABLE, ERR_UNKNOWN_COMMAND, ERR_UNKNOWN_OPTION,
	ERR_SYNTAX_ERROR, ERR_NO_MEDIA, ERR_UNKNOWN_FILESYSTEM,
	ERR_UNKNOWN_ERROR, ERR_MNTCMD_FAILED, ERR_INVALID_ARGUMENT,
	ERR_STRING_TOO_LONG, ERR_BAD_STRING, ERR_TIMEOUT, ERR_NOT_A_FILE
};

typedef enum DEV_TYPES {
	ST_HDD,		ST_MMC,
	ST_CDDA,	ST_USBDISK,
	ST_DVD,		ST_DATACD,
	ST_SVCD,	ST_UNKNOWN,
	ST_VCD,		ST_BLURAY,
	ST_PTP,		ST_MTP,
	ST_FUSE,	ST_USB_CARDREADER
} devt_t;

typedef struct storage_type_s {
	char	*name;
	devt_t	type;
} storage_type_t;

typedef enum IF_TYPES {
	IF_TYPE_DA,	IF_TYPE_ADA,
	IF_TYPE_CD,	IF_TYPE_UGEN,
	IF_TYPE_MMC,	IF_TYPE_FUSE,
	IF_TYPE_MD,	IF_TYPE_LVM,
	IF_TYPE_MTP,	IF_TYPE_PTP,
	IF_TYPE_NVD
} ift_t;

typedef struct iface_s {
	char	*re;
#define RE_DA	"^da[0-9]{1}((s[1-9]{1}[a-h]?)|(p[1-9]{1}))?(\\.eli)?$"
#define RE_UGEN "^ugen[0-9]{1,3}\\.[0-9]{1,2}$"
#define RE_CD	"^cd[0-9]{1}[a-h]?$"
#define RE_ADA	"^ada[0-9]{1}((s[1-9]{1}[a-h]?)|(p[1-9]{1}))?(\\.eli)?$"
#define RE_MMC	"^mmcsd[0-9]{1}((s[1-9]{1}[a-h]?)|(p[1-9]{1}))?(\\.eli)?$"
#define RE_MD	"^md[0-9]{1}((s[1-9]{1}[a-h]?)|(p[1-9]{1}))?(\\.eli)?(\\.uzip)?$"
#define RE_LVM	"^linux_lvm/[a-zA-Z0-9]+"
#define RE_NVD	"^nvd[0-9]{1}((s[1-9]{1}[a-h]?)|(p[1-9]{1}))?(\\.eli)?$"
#define RE_FUSE NULL
#define RE_MTP  NULL
#define RE_PTP  NULL
	ift_t	type;
} iface_t;

/*
 * Struct to manage storage devices
 */
typedef struct sdev_s {
	int	      speed;
	bool	      mounted;
	bool	      cmd_mounted;	  /* Mounted using ext. cmd */
	bool	      dsbmd_mounted;	  /* Mounted through dsbmd. */
	bool	      has_media;
	bool	      polling;		  /* May be polled. */
	bool	      visible;		  /* Visible to client? */
	bool	      ejectable;
	char	      *name;		  /* Volume ID */
	char	      *model;		  /* "<vendor> <product> <revision>" */
	char	      *glabel[NGLBLPRFX]; /* GEOM labels. */
	char	      *dev;		  /* Path to special file */
	char	      *mntpt;		  /* Mountpoint */
	char	      *realdev;		  /* Actual device in case of LVM */
	fs_t	      *fs;		  /* Filesystem type */
	uid_t	      owner;		  /* UID of device's owner. */
	gid_t	      group;		  /* GID of device. */
	const iface_t *iface;		  /* Interface type */
	const storage_type_t *st;  	  /* Media/storage type */
} sdev_t;

struct devlist_s {
	sdev_t *devp;
	SLIST_ENTRY(devlist_s) next;
};

/*
 * Struct to manage clients.
 */
typedef struct client_s {
	int    s;			  /* Client socket. */
	int    id;			  /* Unique ID */
	bool   overflow;		  /* Read command string too long */
	char   buf[64 + PATH_MAX];	  /* String buffer for commands. */
	char   msg[128];		  /* Message buffer. */
	uid_t  uid;			  /* Client UID. */
	gid_t *gids;			  /* Client GIDs. */
	size_t rd;			  /* # of bytes in buffer */
	size_t slen;			  /* Len. of string in buffer. */
} client_t;

struct clilist_s {
	client_t *cli;
	SLIST_ENTRY(clilist_s) next;
};

#endif	/* !_DSBMD_H_ */
