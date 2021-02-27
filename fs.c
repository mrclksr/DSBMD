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
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/disk.h>
#include <sys/mount.h>
#include <ufs/ufs/quota.h>
#include <ufs/ufs/extattr.h>
#include <ufs/ufs/ufsmount.h>
#include <ufs/ufs/dinode.h>
#include <ufs/ffs/fs.h>
#include <sys/endian.h>
#include <libusb20_desc.h>
#include <libusb20.h>
#include <libgeom.h>
#include <unistd.h>
#include <isofs/cd9660/iso.h>
#include <stdbool.h>
#include "common.h"
#include "fs.h"

#define DFLTSBSZ		     512    /* Default super block size. */

#define EXT_SB_PADDING		     1024
#define EXT_MAGIC_OFFS		     0x0038
#define EXT_FEATURE_INCOMP_OFFS	     0x0060
#define EXT_INCOMP_FTYPE	     0x0002
#define EXT_INCOMP_EXTENTS	     0x0040
#define EXT4_INCOMP_MASK	     (EXT_INCOMP_FTYPE | EXT_INCOMP_EXTENTS)

#define ISO9660_PD_OFFSET	     32768  /* Iso primary descriptor offset */
#define ISO9660_ID_OFFSET	     1
#define ISO9660_ID		     "CD001"

#define HFSP_VH_OFFSET		     1024

#define EXFAT_ROOTDIR_CLUSTER_OFFSET 0x60   /* Cluster addr. of root dir */
#define EXFAT_BPS_OFFSET	     0x6c   /* Bytes per sector */
#define EXFAT_SPC_OFFSET	     0x6d   /* Sectors per cluster */
#define EXFAT_CLUSTER_HEAP_OFFSET    0x58   /* Start of cluster heap */ 
#define EXFAT_ENT_TYPE_LABEL	     0x83   /* Volume has label. */
#define EXFAT_ENT_TYPE_NOLABEL	     0x03   /* Volume has no label. */
#define EXFAT_LABEL_LEN_OFFSET	     0x01
#define EXFAT_LABEL_OFFSET	     0x02
#define EXFAT_MAX_LABEL_SIZE	     22
#define EXFAT_MAX_ENTS		     19

#define XFS_SB_OFFSET		     0x00
#define XFS_MAGIC_OFFSET	     0x00
#define XFS_MAX_LABEL_SIZE	     12
#define XFS_LABEL_OFFSET	     0x6c
#define XFS_MAGIC		     "XFSB"

#define BTRFS_SB_OFFSET		     0x10000
#define BTRFS_MAGIC_OFFSET	     0x40
#define BTRFS_LABEL_OFFSET	     0x12b
#define BTRFS_MAX_LABEL_SIZE	     0x100
#define BTRFS_MAGIC		     "_BHRfS_M"

static bool is_fat(int);
static bool is_ntfs(int);
static bool is_exfat(int);
static bool is_ufs(int);
static bool is_ext(int);
static bool is_ext4(int);
static bool is_iso9660(int);
static bool is_hfsp(int);
static bool is_xfs(int);
static bool is_btrfs(int);

fs_t fstype[] = {
	{ "ufs",      UFS,     NULL, NULL,    NULL },
	{ "cd9660",   CD9660,  NULL, NULL,    NULL },
	{ "msdosfs",  MSDOSFS, NULL, NULL,    NULL },
	{ "ntfs",     NTFS,    NULL, NULL,    NULL },
	{ "ext2fs",   EXT,     NULL, NULL,    NULL },
	{ "ext2fs",   EXT4,    NULL, NULL,    NULL },
	{ "exfat",    EXFAT,   NULL, NULL,    NULL },
	{ "fuse",     FUSEFS,  NULL, NULL,    NULL },
	{ "mtpfs",    MTPFS,   NULL, NULL,    NULL },
	{ "ptpfs",    PTPFS,   NULL, NULL,    NULL },
	{ "hfsp",     HFSP,    NULL, NULL,    NULL },
	{ "xfs",      XFS,     NULL, NULL,    NULL },
	{ "btrfs",    BTRFS,   NULL, NULL,    NULL }
};

const int nfstypes = sizeof(fstype) / sizeof(fstype[0]);

static struct getfs_s {
	bool (*chkf)(int);
	FSID type;
} getfsd[] = {
	{ is_fat,      MSDOSFS },
	{ is_ntfs,     NTFS    },
	{ is_exfat,    EXFAT   },
	{ is_ufs,      UFS     },
	{ is_ext4,     EXT4    },
	{ is_ext,      EXT     },
	{ is_iso9660,  CD9660  },
	{ is_hfsp,     HFSP    },
	{ is_xfs,      XFS     },
	{ is_btrfs,    BTRFS   }
};

static uint8_t *
bbread(int fd, long offs, size_t size)
{
	int	       d, r;
	uint8_t	       *p;
	static size_t  blocksize = 0, bufsz = 0, rd, toread;
	static uint8_t *buf = NULL;

	if (ioctl(fd, DIOCGSECTORSIZE, &blocksize) == -1)
		warn("getfs(): ioctl()");
	if (blocksize <= 0)
		blocksize = DFLTSBSZ;
	d = offs / blocksize;
	r = offs % blocksize;
	toread = blocksize * (size / blocksize + !!(size % blocksize));

	if (bufsz < toread) {
		if ((p = realloc(buf, toread)) == NULL) {
			warn("getfs(): realloc()");
			return (NULL);
		}
		buf = p;
		bufsz = toread;
	}
	if (lseek(fd, d * blocksize, SEEK_SET) == -1) {
		warn("getfs(): lseek()");
		return (NULL);
	}
	while ((rd = read(fd, buf, toread)) < toread) {
		if (errno != EINTR) {
			warn("getfs(): read() == %zu", rd);
			return (NULL);
		}
	}
	errno = 0;
	return (buf + r);
}

/*
 * NTFS PROBING
 *
 * 0x00  - 0x02	  jmp instruction
 * 0x03  - 0x0a	  OEM string ("NTFS    ")
 *
 * BPB
 * 0x0b  - 0x0c	  Bytes per sector
 * 0x0d		  Sectors per cluster
 * 0x0e	 - 0x15	  Reserved bytes, all 0.
 * 0x30  - 0x37	  Logical Cluster Number where MFT starts
 *
 * 0x1fe - 0x1ff  0x55 0xaa
 */

static bool
is_ntfs(int dev)
{
	int i;
	uint8_t *sector, spc;
	uint16_t bps;
	uint64_t mft[2];
	
	if ((sector = bbread(dev, 0, DFLTSBSZ)) == NULL)
		return (false);
	/* Check for boot sector signature */
	if (le16dec(&sector[0x1fe]) != 0xaa55)
		return (false);
	/* Check if OEM label exists. */
	if (strncmp((char *)&sector[0x03], "NTFS    ", 8) != 0)
		return (false);
	/* The reserved fields from 0x0e - 0x15 must be 0 */
	if (memcmp(&sector[0x0e], "\0\0\0\0\0\0\0", 7) != 0)
		return (false);
	spc = sector[0x0d];
	bps = le16dec(&sector[0x0b]);

	mft[0] = le64dec(&sector[0x30]);
        mft[1] = le64dec(&sector[0x38]);
	
	for (i = 0; i < 2; i++) {
		if ((sector = bbread(dev, bps * spc * mft[i], 512)) == NULL)
			continue;
		if (strncmp((char *)sector, "FILE", 4) == 0)
			return (true);
	}
	return (false);
}

/*
 * FAT PROBING
 *
 * 0x00  - 0x02	  jmp instruction
 * 0x03  - 0x0a	  OEM string
 *
 * BPB
 * 0x0b  - 0x0c	  Bytes per sector
 * 0x0d		  Logical sectors per cluster
 * 0x0e	 - 0x0f	  Number of reserved logical sectors
 * 0x11  - 0x12	  Max. # of FAT12/16 root dir. entries
 *
 * Extended BPB
 * 0x26		  Extended boot signature
 *
 * FAT32 Extended BPB
 * 0x30  - 0x31	  Logical sector of FS Information Sector
 *
 * 0x1fe - 0x1ff  0x55 0xaa
 */

static bool
is_fat(int dev)
{
	int	 i;
	uint8_t  *sector;
	uint16_t fsisecno, bps;

	if ((sector = bbread(dev, 0, DFLTSBSZ)) == NULL)
		return (false);
	/* Check for boot sector signature */
	if (le16dec(&sector[0x1fe]) != 0xaa55)
		return (false);

	/* Get bytes per sector */
	bps = le16dec(&sector[0x0b]);

	/* Check for number of clusters: 1, 2, 4, 8, ..., or 128 */
	for (i = 0; i < 8 && sector[0x0d] != (1 << i); i++)
		;
	if ((1 << i) != sector[0x0d])
		return (false);
	/* # of reserved logical sectors. Should be > 0. */
	if (le16dec(&sector[0x0e]) < 1)
		return (false);
	/* Check for max. # of root directory entries. */
	if (le16dec(&sector[0x11]) == 0) {
		/* Probably FAT32. Check for FAT32 Extended BPB */
		fsisecno = le16dec(&sector[0x30]);
		if (fsisecno == 0 || fsisecno == 0xffff)
			/* Try sector 1. */
			fsisecno = 1;
		if ((sector = bbread(dev, fsisecno * bps, bps)) == NULL)
			return (false);
		/* Check for FS Information Sector signature. */
		if (strncmp((char *)sector, "RRaA", 4) == 0)
			return (true);
	} else if (sector[0x26] == 0x29) {
		if (strncmp((char *)&sector[0x36], "FAT", 3) == 0)
			return (true);
		/* Probably FAT12 or FAT16 */
	} else if (sector[0x26] == 0x28)
		return (true);
	return (false);
}

static bool
is_exfat(int dev)
{
	uint8_t *p;

	if ((p = bbread(dev, 0, DFLTSBSZ)) == NULL)
		return (false);
	if (strncmp((char *)&p[3], "EXFAT", 5) == 0)
		return (true);
	return (false);
}

static bool
is_hfsp(int dev)
{
	uint8_t *p;

	if ((p = bbread(dev, HFSP_VH_OFFSET, 2)) == NULL)
		return (false);
	if (strncmp((char *)p, "H+", 2) == 0 ||
	    strncmp((char *)p, "Hx", 2) == 0)
		return (true);
	return (false);
}

static bool
is_ufs(int dev)
{
	int	     i;
	uint8_t	    *p;
	struct fs   *fs;
	const u_int blocksearch[] = SBLOCKSEARCH;

	for (i = 0; blocksearch[i] != -1; i++) {
		if ((p = bbread(dev, blocksearch[i], SBLOCKSIZE)) == NULL)
			continue;
		fs = (struct fs *)p;
		if (fs->fs_magic == FS_UFS1_MAGIC ||
		    fs->fs_magic == FS_UFS2_MAGIC)
			return (true);
	}
	return (false);
}

static bool
is_ext(int dev)
{
	uint8_t *p;

	if ((p = bbread(dev, EXT_SB_PADDING, DFLTSBSZ)) == NULL)
		return (false);
	if (p[EXT_MAGIC_OFFS] == 0x53 && p[EXT_MAGIC_OFFS + 1] == 0xef)
		return (true);
	return (false);
}

static bool
is_ext4(int dev)
{
	int	i;
	uint8_t *p;
	uint32_t incomp;

	if (!is_ext(dev))
		return (false);
	if ((p = bbread(dev, EXT_SB_PADDING, DFLTSBSZ)) == NULL)
		return (false);
	incomp = le32dec(&p[EXT_FEATURE_INCOMP_OFFS]);
	/*
	 * If there are features set not yet supported by ext2fs(5),
	 * treat filesystem as Ext4.
	 */
	for (i = 0; i < sizeof(incomp) * 8; i++) {
		if ((incomp & (1 << i)) && !((1 << i) & EXT4_INCOMP_MASK))
			return (true);
	}
	return (false);
}

static bool
is_iso9660(int dev)
{
	char *p;

	if ((p = (char *)bbread(dev, ISO9660_PD_OFFSET, 12)) == NULL)
		return (false);
	if (strncmp(&p[ISO9660_ID_OFFSET], ISO9660_ID, strlen(ISO9660_ID)) == 0)
		return (true);
	return (false);
}

static bool
is_xfs(int dev)
{
	uint8_t *p;

	if ((p = bbread(dev, XFS_SB_OFFSET, DFLTSBSZ)) == NULL)
		return (false);
	if (strncmp((char *)&p[XFS_MAGIC_OFFSET], XFS_MAGIC,
	    strlen(XFS_MAGIC)) == 0)
		return (true);
	return (false);
}

static bool
is_btrfs(int dev)
{
	uint8_t *p;

	if ((p = bbread(dev, BTRFS_SB_OFFSET, DFLTSBSZ)) == NULL)
		return (false);
	if (strncmp((char *)&p[BTRFS_MAGIC_OFFSET], BTRFS_MAGIC,
	    strlen(BTRFS_MAGIC)) == 0)
		return (true);
	return (false);
}

fs_t *
getfs(const char *disk)
{
	int i, j, fd;

	if ((fd = open(disk, O_RDONLY)) == -1) {
		warn("open(%s)", disk);
		return (NULL);
	}
	for (i = 0; i < sizeof(getfsd) / sizeof(struct getfs_s); i++) {
		if (getfsd[i].chkf(fd)) {
			for (j = 0; j < nfstypes; j++) {
				if (getfsd[i].type == fstype[j].id) {
					(void)close(fd);
					return (&fstype[j]);
				}
			}
		} else if (errno > 0)
			warn("getfs()");
	}
	(void)close(fd);

	return (NULL);
}

char *
get_exfat_label(const char *dev)
{
	int	    fd;
	u_int	     frdc, bps, spc, offs, cho, i, chs;
	u_char	    *p;
	static char  label[EXFAT_MAX_LABEL_SIZE];

	if ((fd = open(dev, O_RDONLY)) == -1) {
		warn("get_exfat_label(): open(%s)", dev);
		return (NULL);
	}
	if ((p = bbread(fd, 0, DFLTSBSZ)) == NULL) {
		warn("get_exfat_label(): bbread()");
		(void)close(fd);
		return (NULL);
	}
	frdc = le32dec(&p[EXFAT_ROOTDIR_CLUSTER_OFFSET]);
	cho  = le32dec(&p[EXFAT_CLUSTER_HEAP_OFFSET]);
	bps  = 1 << p[EXFAT_BPS_OFFSET];
	spc  = 1 << p[EXFAT_SPC_OFFSET];

	/* Cluster heap start */
	chs = cho * bps + (bps * spc) * (frdc - 2);

	for (offs = 0; offs < EXFAT_MAX_ENTS; offs++) {
		if ((p = bbread(fd, chs + offs * 32, 32)) == NULL) {
			warn("get_exfat_label(): bbread()");
			(void)close(fd);
			return (NULL);
		}
		if (p[0] == EXFAT_ENT_TYPE_NOLABEL)
			return (NULL);
		else if (p[0] == EXFAT_ENT_TYPE_LABEL) {
			for (i = 0; i < p[EXFAT_LABEL_LEN_OFFSET] && 
			            i < EXFAT_MAX_LABEL_SIZE / 2; i++) {
				/* ATM, we're only accepting ASCII labels. */
				if (p[EXFAT_LABEL_OFFSET + 2 * i + 1] != 0) {
					(void)close(fd);
					return (NULL);
				}
				label[i] = p[EXFAT_LABEL_OFFSET + i * 2];
			}
			label[i] = 0;
			(void)close(fd);
			return (label);
		}
	}
	(void)close(fd);
	return (NULL);
}

/*
 * Gets the vol ID from a CDROM with a ISO9660 filesystem installed. It was
 * necessary to write my own function, since GEOM labels don't seem to work
 * reliable with CD ISO9660.
 */
char *
cd9660_get_volid(const char *path)
{
	int	    fd;
	static char volid[32], *sector, *p, *q;
	struct iso_primary_descriptor *ip;

	if ((fd = g_open(path, 0)) == -1) {
		logprint("Couldn't open %s", path); return (NULL);
	}
	if (g_sectorsize(fd) != ISO_DEFAULT_BLOCK_SIZE) {
		/* Could be an audio or a raw CD */
		(void)g_close(fd); return (NULL);
	}
	if (lseek(fd, 16 * ISO_DEFAULT_BLOCK_SIZE, SEEK_SET) == -1) {
		logprint("lseek()"); (void)g_close(fd);
		return (NULL);
	}
	if ((sector = malloc(ISO_DEFAULT_BLOCK_SIZE)) == NULL)
		err(EXIT_FAILURE, "malloc()");
	if (read(fd, sector, ISO_DEFAULT_BLOCK_SIZE) == -1) {
		logprint("read()"); free(sector); return (NULL);
	}
	(void)close(fd);
	ip = (struct iso_primary_descriptor *)sector;
	if (memcmp(ISO_STANDARD_ID, ip->id, strlen(ISO_STANDARD_ID)) == 0 ||
	    memcmp(ISO_SIERRA_ID, ip->id, strlen(ISO_SIERRA_ID)) == 0     ||
	    memcmp(ISO_ECMA_ID, ip->id, strlen(ISO_ECMA_ID)) == 0) {
		p = strncpy(volid, ip->volume_id, sizeof(volid) - 1);
		for (q = p + strlen(volid) - 1; q > p && *q == ' '; q--)
			*q = '\0';
	} else
		p = NULL;
	free(sector);

	return (p);
}

char *
get_xfs_label(const char *path)
{
	int	    fd;
	u_char	    *p;
	static char  label[XFS_MAX_LABEL_SIZE];

	if ((fd = open(path, O_RDONLY)) == -1) {
		warn("get_xfs_label(): open(%s)", path);
		return (NULL);
	}
	p = bbread(fd, XFS_LABEL_OFFSET, sizeof(label));
	(void)close(fd);
	if (p == NULL) {
		warn("get_xfs_label(): bbread()");
		return (NULL);
	}
	(void)strlcpy(label, (char *)p, sizeof(label) - 1);
	return (label);
}

char *
get_btrfs_label(const char *path)
{
	int	fd;
	u_char	    *p;
	static char  label[BTRFS_MAX_LABEL_SIZE];

	if ((fd = open(path, O_RDONLY)) == -1) {
		warn("get_btrfs_label(): open(%s)", path);
		return (NULL);
	}
	p = bbread(fd, BTRFS_SB_OFFSET, sizeof(label));
	(void)close(fd);
	if (p == NULL) {
		warn("get_btrfs_label(): bbread()");
		return (NULL);
	}
	(void)strlcpy(label, (char *)&p[BTRFS_LABEL_OFFSET],
	    sizeof(label) - 1);
	return (label);
}

/*
 * Return a drive's glabel with the given prefix, or return the first matching
 * glabel if 'prefix' is NULL.
 */
char *
get_geom_label(const char *path, const char *prefix)
{
	static char	 label[128];
	struct gmesh	 mesh;
	struct ggeom	 *gp;
	struct gclass	 *cp;
	struct gprovider *pp;

	path = devbasename(path);
	if (geom_gettree(&mesh) != 0)
		return (NULL);
	cp = NULL;
	LIST_FOREACH(cp, &mesh.lg_class, lg_class) {
		if (strcmp(cp->lg_name, "LABEL") == 0)
			break;
	}
	if (cp == NULL) {
		geom_deletetree(&mesh);
		return (NULL);
	}
	LIST_FOREACH(gp, &cp->lg_geom, lg_geom) {
		if (LIST_EMPTY(&gp->lg_provider))
			continue;
		if (strcmp(path, gp->lg_name) != 0)
			continue;
		pp = LIST_FIRST(&gp->lg_provider);
		if (pp == NULL || pp->lg_name == NULL) {
			geom_deletetree(&mesh);
			return (NULL);
		}
		if (prefix != NULL &&
		    strncmp(pp->lg_name, prefix, strlen(prefix)) == 0 &&
		    pp->lg_name[strlen(prefix)] == '/') {
			(void)strncpy(label, pp->lg_name, sizeof(label));
			geom_deletetree(&mesh);
			return (label);
		} else if (prefix == NULL) {
			(void)strncpy(label, pp->lg_name, sizeof(label));
			geom_deletetree(&mesh);
			return (label);
		}

	}
	geom_deletetree(&mesh);
	return (NULL);
}

static char *
get_ugen_label(const char *ugen)
{
	int	    bus, addr;
	bool	    found;
	static char *p, buf[256];
	struct libusb20_device	*pdev;
	struct libusb20_backend	*pbe;
	struct LIBUSB20_DEVICE_DESC_DECODED *ddesc;

	if (!get_ugen_bus_and_addr(ugen, &bus, &addr))
		return (NULL);
	pbe = libusb20_be_alloc_default();
	for (found = false, pdev = NULL, p = NULL;
	    !found && (pdev = libusb20_be_device_foreach(pbe, pdev));) {
		if (libusb20_dev_get_bus_number(pdev) == bus &&
		    libusb20_dev_get_address(pdev) == addr) {
			found = true;
			if (libusb20_dev_open(pdev, 0))
				err(EXIT_FAILURE, "libusb20_dev_open()");
			ddesc = libusb20_dev_get_device_desc(pdev);
			if (ddesc != NULL) {
				if (!libusb20_dev_req_string_simple_sync(pdev,
				    ddesc->iProduct, buf, sizeof(buf) - 1))
					p = buf;
			}
			if (libusb20_dev_close(pdev))
                        	err(EXIT_FAILURE, "libusb20_dev_close()");
		}
	}
	libusb20_be_free(pbe);

	return (!found ? NULL : p);
}


/*
 * Reads the vol ID from various filesystems.
 */
char *
get_label(const char *dev, const char *fs)
{
	char *label, *p, *path;
	
	if (fs == NULL)
		return (NULL);
	path = devpath(dev);
	if (strcmp(fs, "ptpfs") == 0 || strcmp(fs, "mtpfs") == 0)
		return (get_ugen_label(dev));
	if (strcmp(fs, "msdosfs") == 0)
		label = get_geom_label(path, "msdosfs");
	else if (strcmp(fs, "btrfs") == 0)
		label = get_btrfs_label(path);
	else if (strcmp(fs, "xfs") == 0)
		label = get_xfs_label(path);
	else if (strcmp(fs, "ufs") == 0) {
		if ((label = get_geom_label(path, "label")) == NULL &&
		    (label = get_geom_label(path, "ufs")) == NULL &&
		    (label = get_geom_label(path, "gpt")) == NULL)
			label = get_geom_label(path, "ufsid");
	} else if (strcmp(fs, "cd9660") == 0)
		label = cd9660_get_volid(path);
	else if (strcmp(fs, "exfat") == 0)
		label = get_exfat_label(path);
	else if (strcmp(fs, "ntfs") == 0)
		label = get_geom_label(path, "ntfs");
	else if ((label = get_geom_label(path, "gpt")) == NULL)
		label = get_geom_label(path, NULL);
	if (label != NULL) {
		if ((p = strchr(label, '/')) != NULL)
			label = p + 1;
	}
	return (label);
}

