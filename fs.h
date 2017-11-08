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

#ifndef _FS_H_
#define _FS_H_

typedef enum FSID {
	UFS, CD9660, MSDOSFS, NTFS, ZFS, EXFAT, EXT, REISERFS, XFS, FUSEFS,
	MTPFS, PTPFS, NFSTYPES
} FSID;

/*
 * Fileysystem types.
 */
typedef struct fs_s {
	const char *name;
	FSID	   id;
	const char *mntcmd;   /* User defined mount command */
	const char *mntcmd_u; /* User defined mount command for user mode */
	const char *dopts;    /* Default mount options. */
	const char *uopts;    /* User defined mount options. */
} fs_t;

extern fs_t fstype[];

extern fs_t *getfs(const char *);
extern char *get_exfat_label(const char *);
extern char *cd9660_get_volid(const char *);
extern char *get_label(const char *, const char *);
extern char *get_geom_label(const char *, const char *);
#endif	/* !_FS_H_ */

