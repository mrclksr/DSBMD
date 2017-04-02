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

enum {
	CFG_MNTDIR, CFG_CD9660_MNTCMD, CFG_MSDOSFS_MNTCMD, CFG_NTFS_MNTCMD,
	CFG_UFS_MNTCMD, CFG_EXT_MNTCMD, CFG_EXFAT_MNTCMD, CFG_REISERFS_MNTCMD,
	CFG_XFS_MNTCMD,

	CFG_CD9660_OPTS, CFG_MSDOSFS_OPTS, CFG_NTFS_OPTS, CFG_UFS_OPTS,
	CFG_EXT_OPTS, CFG_EXFAT_OPTS, CFG_REISERFS_OPTS, CFG_XFS_OPTS,

	CFG_CDRSPEED, CFG_MAX_CLIENTS, CFG_POLL_INTERVAL, CFG_POLL_EXCEPTIONS,
	CFG_ALLOW_USERS, CFG_ALLOW_GROUPS, CFG_NVARS
};

extern dsbcfg_vardef_t vardefs[];

