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

#include <err.h>
#include <string.h>

#include "dsbcfg/dsbcfg.h"
#include "config.h"

#define VAL(v) DSBCFG_VAL(v)

#define HEADER() do { \
	warnx(hl); warnx("WARNING"); warnx(""); \
} while (0)

#define FOOTER() do { \
	warnx(""); warnx("%s\n", hl); \
} while (0)

static const char hl[] = "***********************************************" \
		  	 "******************";

dsbcfg_vardef_t vardefs[] = {
{ "mount_dir",		   DSBCFG_VAR_STRING,  CFG_MNTDIR		     },
{ "cd9660_mount_cmd",	   DSBCFG_VAR_STRING,  CFG_CD9660_MNTCMD	     },
{ "msdosfs_mount_cmd",	   DSBCFG_VAR_STRING,  CFG_MSDOSFS_MNTCMD	     },
{ "ntfs_mount_cmd",	   DSBCFG_VAR_STRING,  CFG_NTFS_MNTCMD		     },
{ "hfsp_mount_cmd",	   DSBCFG_VAR_STRING,  CFG_HFSP_MNTCMD		     },
{ "ufs_mount_cmd",	   DSBCFG_VAR_STRING,  CFG_UFS_MNTCMD		     },
{ "ext_mount_cmd",	   DSBCFG_VAR_STRING,  CFG_EXT_MNTCMD		     },
{ "ext4_mount_cmd",	   DSBCFG_VAR_STRING,  CFG_EXT4_MNTCMD		     },
{ "exfat_mount_cmd",	   DSBCFG_VAR_STRING,  CFG_EXFAT_MNTCMD		     },
{ "mtpfs_mount_cmd",	   DSBCFG_VAR_STRING,  CFG_MTPFS_MNTCMD		     },
{ "ptpfs_mount_cmd",	   DSBCFG_VAR_STRING,  CFG_PTPFS_MNTCMD		     },
{ "xfs_mount_cmd",	   DSBCFG_VAR_STRING,  CFG_XFS_MNTCMD		     },
{ "btrfs_mount_cmd",	   DSBCFG_VAR_STRING,  CFG_BTRFS_MNTCMD		     },
{ "cd9660_mount_cmd_usr",  DSBCFG_VAR_STRING,  CFG_CD9660_MNTCMD_U	     },
{ "msdosfs_mount_cmd_usr", DSBCFG_VAR_STRING,  CFG_MSDOSFS_MNTCMD_U	     },
{ "ntfs_mount_cmd_usr",	   DSBCFG_VAR_STRING,  CFG_NTFS_MNTCMD_U	     },
{ "hfsp_mount_cmd_usr",	   DSBCFG_VAR_STRING,  CFG_HFSP_MNTCMD_U	     },
{ "ufs_mount_cmd_usr",	   DSBCFG_VAR_STRING,  CFG_UFS_MNTCMD_U     	     },
{ "ext_mount_cmd_usr",	   DSBCFG_VAR_STRING,  CFG_EXT_MNTCMD_U     	     },
{ "ext4_mount_cmd_usr",	   DSBCFG_VAR_STRING,  CFG_EXT4_MNTCMD_U     	     },
{ "exfat_mount_cmd_usr",   DSBCFG_VAR_STRING,  CFG_EXFAT_MNTCMD_U   	     },
{ "mtpfs_mount_cmd_usr",   DSBCFG_VAR_STRING,  CFG_MTPFS_MNTCMD_U   	     },
{ "ptpfs_mount_cmd_usr",   DSBCFG_VAR_STRING,  CFG_PTPFS_MNTCMD_U   	     },
{ "xfs_mount_cmd_usr",	   DSBCFG_VAR_STRING,  CFG_XFS_MNTCMD_U		     },
{ "btrfs_mount_cmd_usr",   DSBCFG_VAR_STRING,  CFG_BTRFS_MNTCMD_U	     },
{ "cd9660_opts",	   DSBCFG_VAR_STRING,  CFG_CD9660_OPTS	     	     },
{ "msdosfs_opts",	   DSBCFG_VAR_STRING,  CFG_MSDOSFS_OPTS     	     },
{ "msdosfs_locale",	   DSBCFG_VAR_STRING,  CFG_MSDOSFS_LOCALE   	     },
{ "hfsp_opts",		   DSBCFG_VAR_STRING,  CFG_HFSP_OPTS	     	     },
{ "ntfs_opts",		   DSBCFG_VAR_STRING,  CFG_NTFS_OPTS	     	     },
{ "ufs_opts",		   DSBCFG_VAR_STRING,  CFG_UFS_OPTS	     	     },
{ "ext_opts",		   DSBCFG_VAR_STRING,  CFG_EXT_OPTS	     	     },
{ "ext4_opts",		   DSBCFG_VAR_STRING,  CFG_EXT4_OPTS	     	     },
{ "exfat_opts",		   DSBCFG_VAR_STRING,  CFG_EXFAT_OPTS	     	     },
{ "mtpfs_opts",		   DSBCFG_VAR_STRING,  CFG_MTPFS_OPTS	     	     },
{ "ptpfs_opts",		   DSBCFG_VAR_STRING,  CFG_PTPFS_OPTS	     	     },
{ "xfs_opts",		   DSBCFG_VAR_STRING,  CFG_XFS_OPTS	     	     },
{ "btrfs_opts",		   DSBCFG_VAR_STRING,  CFG_BTRFS_OPTS	     	     },
{ "unmount_on_exit",	   DSBCFG_VAR_STRING,  CFG_UNMOUNT_ON_EXIT, VAL("no")},
{ "procmaxwait",	   DSBCFG_VAR_INTEGER, CFG_PROCMAXWAIT,     VAL(10)  },
{ "cdrspeed",		   DSBCFG_VAR_INTEGER, CFG_CDRSPEED,	    VAL(16)  },
{ "max_clients",	   DSBCFG_VAR_INTEGER, CFG_MAX_CLIENTS,     VAL(10)  },
{ "poll_interval",	   DSBCFG_VAR_INTEGER, CFG_POLL_INTERVAL,   VAL(-1)  },
{ "mntchk_interval",	   DSBCFG_VAR_INTEGER, CFG_MNTCHK_INTERVAL, VAL(1)   },
{ "usermount",		   DSBCFG_VAR_BOOLEAN, CFG_USERMOUNT,	    VAL(true)},
{ "poll_exceptions",	   DSBCFG_VAR_STRINGS, CFG_POLL_EXCEPTIONS           },
{ "allow_users",	   DSBCFG_VAR_STRINGS, CFG_ALLOW_USERS	      	     },
{ "allow_groups",	   DSBCFG_VAR_STRINGS, CFG_ALLOW_GROUPS		     },
{ "preload_kmods",	   DSBCFG_VAR_STRINGS, CFG_PRELOAD_KMODS	     },
{ "cfgversion",		   DSBCFG_VAR_INTEGER, CFG_CFG_VERSION,	    VAL(0)   }
};

const int nvardefs = sizeof(vardefs) / sizeof(dsbcfg_vardef_t);

void
check_cfg_version(dsbcfg_t *cfg)
{

	if (dsbcfg_getval(cfg, CFG_CFG_VERSION).integer < CFGVERSION) {
		HEADER();
		warnx("Your dsbmd.conf seems to be outdated. Please " 	\
		      "recreate it from");
		warnx("dsbmd.conf.sample, or merge the files.");
		FOOTER();
	}
}

void
check_cfg_opts(dsbcfg_t *cfg)
{
	bool polliv, pollex;
#if FREEBSD_VERSION >= 12
	/* In case of FreeBSD >= 12 and msdosfs: remove the "large" option. */
	bool large = false;
	char *p, *mopts;

	mopts = dsbcfg_getval(cfg, CFG_MSDOSFS_OPTS).string;
	if (mopts == NULL)
		return;
	do {
		if ((p = strstr(mopts, ",large")) != NULL ||
		    (p = strstr(mopts, "large,")) != NULL)
			(void)memmove(p, p + 6, strlen(p + 6) + 1);
		else if ((p = strstr(mopts, "large")) != NULL)
			memmove(p, p + 5, strlen(p + 5) + 1);
		if (p != NULL)
			large = true;
	} while (p != NULL);

	if (!large)
		return;
	HEADER();
	warnx("Ignoring deprecated 'large' mount option for msdosfs.");
	warnx("On FreeBSD >= 12 (as of r319735) this option was removed.");
	warnx("");
	warnx("Please adjust your dsbmd.conf.");
	FOOTER();
#endif
	pollex = polliv = false;
	if (dsbcfg_getval(cfg, CFG_POLL_EXCEPTIONS).strings != NULL)
		pollex = true;
	if (dsbcfg_getval(cfg, CFG_POLL_INTERVAL).integer != -1)
		polliv = true;
	if (pollex || polliv) {
		HEADER();
		if (pollex)
			warnx("Ignoring deprecated 'poll_exceptions' variable");
		if (polliv)
			warnx("Ignoring deprecated 'poll_interval' variable");
		FOOTER();
	}
}

