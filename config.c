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

#include "dsbcfg/dsbcfg.h"
#include "config.h"

dsbcfg_vardef_t vardefs[] = {
	{ "mount_dir",	        DSBCFG_VAR_STRING,  CFG_MNTDIR		 },
	{ "cd9660_mount_cmd",   DSBCFG_VAR_STRING,  CFG_CD9660_MNTCMD	 },
	{ "msdosfs_mount_cmd",  DSBCFG_VAR_STRING,  CFG_MSDOSFS_MNTCMD	 },
	{ "ntfs_mount_cmd",     DSBCFG_VAR_STRING,  CFG_NTFS_MNTCMD	 },
	{ "ufs_mount_cmd",      DSBCFG_VAR_STRING,  CFG_UFS_MNTCMD	 },
	{ "ext_mount_cmd",      DSBCFG_VAR_STRING,  CFG_EXT_MNTCMD	 },
	{ "exfat_mount_cmd",    DSBCFG_VAR_STRING,  CFG_EXFAT_MNTCMD	 },
	{ "reiserfs_mount_cmd", DSBCFG_VAR_STRING,  CFG_REISERFS_MNTCMD  },
	{ "xfs_mount_cmd",      DSBCFG_VAR_STRING,  CFG_XFS_MNTCMD	 },
	{ "cd9660_opts",        DSBCFG_VAR_STRING,  CFG_CD9660_OPTS	 },
	{ "msdosfs_opts",       DSBCFG_VAR_STRING,  CFG_MSDOSFS_OPTS	 },
	{ "ntfs_opts",          DSBCFG_VAR_STRING,  CFG_NTFS_OPTS	 },
	{ "ufs_opts",	        DSBCFG_VAR_STRING,  CFG_UFS_OPTS	 },
	{ "ext_opts",           DSBCFG_VAR_STRING,  CFG_EXT_OPTS	 },
	{ "exfat_opts",         DSBCFG_VAR_STRING,  CFG_EXFAT_OPTS	 },
	{ "reiserfs_opts",      DSBCFG_VAR_STRING,  CFG_REISERFS_OPTS	 },
	{ "xfs_opts",	        DSBCFG_VAR_STRING,  CFG_XFS_OPTS	 },
	{ "cdrspeed",	        DSBCFG_VAR_INTEGER, CFG_CDRSPEED	 },
	{ "max_clients",        DSBCFG_VAR_INTEGER, CFG_MAX_CLIENTS	 },
	{ "poll_interval",      DSBCFG_VAR_INTEGER, CFG_POLL_INTERVAL	 },
	{ "poll_exceptions",    DSBCFG_VAR_STRINGS, CFG_POLL_EXCEPTIONS  },
	{ "allow_users",        DSBCFG_VAR_STRINGS, CFG_ALLOW_USERS	 },
	{ "allow_groups",       DSBCFG_VAR_STRINGS, CFG_ALLOW_GROUPS	 }
};

