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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/ata.h>
#include <sys/cdio.h>
#include <sys/cdrio.h>
#include <sys/disk.h>
#include <sys/disklabel.h>
#include <sys/iconv.h>
#include <sys/param.h>
#include <sys/linker.h>
#include <sys/module.h>
#include <unistd.h>
#include <vm/vm_param.h>
#include <dirent.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <paths.h>
#include <fstab.h>
#include <pwd.h>
#include <grp.h>
#include <err.h>
#include <errno.h>
#include <camlib.h>
#include <cam/cam_ccb.h>
#include <cam/scsi/scsi_pass.h>
#include <cam/scsi/scsi_message.h>
#include <libgeom.h>
#include <libutil.h>
#include <isofs/cd9660/iso.h>
#include "common.h"
#include "fs.h"
#include "dsbmd.h"
#include "dsbcfg/dsbcfg.h"
#include "config.h"
#include <sys/iconv.h>

#define MAXDEVS		64
#define MNTDIRPERM	(S_IRWXU | S_IXGRP | S_IRGRP | S_IXOTH | S_IROTH)
#define NCOMMANDS	(sizeof(commands) / sizeof(struct command_s))
#define NDISK_TYPES	(sizeof(disktypes) / sizeof(disktypes[0]))
#define NDISK_CLASSES	(sizeof(disk_classes) / sizeof(disk_classes[0]))
#define MNTCHK_INTERVAL	1000000

static int		get_cdrtype(const char *);
static int		mymount(const char *, const char *, const char *,
			    const char *, uid_t, gid_t);
static int		mount_drive(client_t *, drive_t *drvp);
static int		unmount_drive(client_t *, drive_t *, bool, bool);
static int		extend_iovec(struct iovec **, int *, const char *,
			    const char *);
static int		eject_media(client_t *, drive_t *, bool);
static int		set_cdrspeed(client_t *, drive_t *, int);
static int		set_msdosfs_locale(const char *, struct iovec**, int *);
static int		waitforbytes(FILE *);
static bool		match_part_dev(const char *, size_t);
static bool		has_media(const char *);
static bool		is_parted(const char *);
static bool		is_atapicam(const char *);
static bool		is_mountable(const char *);
static bool		is_mntpt(const char *);
static bool		check_permission(uid_t, gid_t *);
static bool		usermount_set(void);
static FILE		*uconnect(const char *);
static char		*read_devd_event(FILE *);
static char		**extend_list(char **, int *, const char *);
static char		*getmntpt(drive_t *);
static char		*get_cam_modelname(const char *);
static char		*get_ata_modelname(const char *);
static char		*get_diskname(const char *);
static char		*get_lv_dev(const char *);
static char		*dev_from_gptid(const char *);
static void		process_devd_event(char *);
static void		usage(void);
static void		switcheids(uid_t, gid_t);
static void		restoreids(void);
static void		rmntpt(const char *);
static void		cleanup(int);
static void		del_drive(drive_t *);
static void		*serve_client(void *);
static void		del_client(client_t *);
static void		update_drive(drive_t *);
static void		parse_devd_event(char *);
static void		free_iovec(struct iovec *);
static void		add_to_pollqueue(drive_t *);
static void		del_from_pollqueue(drive_t *);
static void		exec_cmd(client_t *, char *);
static void		cmd_eject(client_t *, char **);
static void		cmd_speed(client_t *, char **);
static void		cmd_size(client_t *, char **);
static void		cmd_mount(client_t *, char **);
static void		cmd_unmount(client_t *, char **);
static void		cmd_quit(client_t *cli, char **);
static void		notifybc(drive_t *, bool);
static void		notify(client_t *, drive_t *, bool);
static void		cliprint(client_t *, const char *, ...);
static void		cliprintbc(client_t *, const char *, ...);
static void		check_mntbl(struct statfs *sb, int nsb);
static void		check_fuse_mount(struct statfs *sb, int nsb);
static void		check_fuse_unmount(struct statfs *, int);
static void		*thr_check_mntbl(void *);
static drive_t		*add_drive(const char *);
static drive_t		*media_changed(void);
static drive_t		*lookupdrv(const char *);
static client_t		*add_client(int);
static const dskcl_t	*match_disk_pattern(const char *);
static const dsktp_t	*get_disktype(const char *, const dskcl_t *);

/*
 * Struct to represent the fields of a devd notify event.
 */
struct devdevent_s {
	char *system;	 /* Bus or DEVFS */
	char *subsystem; /* Only CDEV is interesting to us. */
	char *type;	 /* Event type: CREATE, DESTROY. */
	char *cdev;	 /* Device name. */
} devdevent;

static const char *glblprfx[NGLBLPRFX] = GLBLPRFX;

const dsktp_t disktypes[] = {
	{ DSK_TYPE_HDD,	    "HDD"	 }, { DSK_TYPE_MMC,	"MMC"	    }, 
	{ CDR_TYPE_RAW,     "RAWCD"	 }, { CDR_TYPE_VCD,	"VCD"	    },
	{ CDR_TYPE_SVCD,    "SVCD"	 }, { CDR_TYPE_DVD,	"DVD"	    },
	{ CDR_TYPE_AUDIO,   "AUDIOCD"	 }, { CDR_TYPE_DATA,	"DATACD"    },
	{ DSK_TYPE_FLOPPY,  "FLOPPY"	 }, { CDR_TYPE_UNKNOWN, "UNKNOWNCD" },
	{ DSK_TYPE_USBDISK, "USBDISK"    }, { DSK_TYPE_FUSE, 	"HDD"	    }
};

const dskcl_t disk_classes[] = {
	{ ATA,	 MSD,    "ad"	      }, { ATA,   CDROM, "acd"	      },
	{ ATA,	 FLOPPY, "afd"	      }, { CAM,   MSD,   "da"	      },
	{ CAM,   CDROM,  "cd"	      }, { CAM,   MSD,   "ada"	      },
	{ MMC,   MSD,    "mmcsd"      }, { OTHER, MD,    "md"	      },
	{ OTHER, FUSE,	 ""           }, { OTHER, LLV,   "linux_lvm/" },
	{ CAM,   LLV,	 "linux_lvm/" }, { ATA,	  LLV,	 "linux_lvm/" }
};

/*
 * Struct to assign command strings/names to a function.
 */
struct command_s {
	const char *cmd;
	void (*cmdf)(client_t *, char **);
} commands[] = {
	{ "quit",    &cmd_quit	  }, { "mount", &cmd_mount },
	{ "unmount", &cmd_unmount }, { "eject", &cmd_eject },
	{ "speed",   &cmd_speed   }, { "size",	&cmd_size  }
};

static int	nclients = 0;		/* # of connected clients. */
static int	ndrives  = 0;		/* # of drives. */
static int	queuesz  = 0;		/* # of devices in poll queue. */
static uid_t    *allow_uids = NULL;	/* UIDs allowed to connect. */
static gid_t    *allow_gids = NULL;	/* GIDs allowed to connect. */
static drive_t	**pollqueue = NULL;	/* List of devices to poll. */
static drive_t	**drives    = NULL;	/* List of mountable drives. */
static client_t **clients   = NULL;	/* List of connected clients. */
static dsbcfg_t *cfg	    = NULL;
static pthread_mutex_t cli_mtx;		/* Mutex for client list mods. */
static pthread_mutex_t drv_mtx;		/* Mutex for drive list mods. */

int
main(int argc, char *argv[])
{
	int	       i, upoll, spoll, ls, cs, sflags, maxfd, ch;
	DIR	       *dirp, *dirp2;
	bool	       fflag;
	FILE	       *s, *fp;
	char	       lvmpath[512], *ev, **v;
	fd_set	       allset, rset;
	drive_t	       *drvp;
	client_t       *cli;
	pthread_t      thr;
	socklen_t      clen;
	struct stat    sb;
	struct group   *gr;
	struct passwd  *pw;
	struct dirent  *dp, *dp2;
	struct timeval tv;
	struct sockaddr_un c_addr, s_addr;

	fflag = false;
	while ((ch = getopt(argc, argv, "fh")) != -1) {
		switch (ch) {
		case 'f':
			fflag = true;
			break;
		case 'h':
		case '?':
			usage();
		}
	}
	/* Check if deamon is already running. */
	if ((fp = fopen(PATH_PID_FILE, "r+")) == NULL) {
		if (errno != ENOENT)
			err(EXIT_FAILURE, "fopen(%s)", PATH_PID_FILE);
		/* Not running - Create the PID/lock file. */
		if ((fp = fopen(PATH_PID_FILE, "w")) == NULL) {
			err(EXIT_FAILURE, "couldn't create pid file %s",
			    PATH_PID_FILE);
		}
	}
	if (lockf(fileno(fp), F_TLOCK, 0) == -1) {
		if (errno == EWOULDBLOCK) {
			/* Daemon already running. */
			errx(EXIT_FAILURE, "%s is already running.", PROGRAM);
		} else
			err(EXIT_FAILURE, "flock()");
	}
	cfg = dsbcfg_read(NULL, PATH_CONFIG, vardefs, CFG_NVARS);
	if (cfg == NULL)
		errx(EXIT_FAILURE, "%s", dsbcfg_strerror());
	/*
	 * Generate UID list of allowed users.
	 */
	for (i = 0, v = dsbcfg_getval(cfg, CFG_ALLOW_USERS).strings;
	    v != NULL && *v != NULL; v++, i++)
		;
	if ((allow_uids = malloc(sizeof(uid_t) * (i + 1))) == NULL)
		err(EXIT_FAILURE, "malloc()");

	for (i = 0, v = dsbcfg_getval(cfg, CFG_ALLOW_USERS).strings;
	    v != NULL && *v != NULL; v++, i++) {
		if ((pw = getpwnam(*v)) == NULL)
			errx(EXIT_FAILURE, "Unknown user '%s'", *v);
		allow_uids[i] = pw->pw_uid;
	}
	endpwent();
	allow_uids[i] = (uid_t)-1;

	/*
	 * Generate GID list of allowed groups.
	 */
	for (i = 0, v = dsbcfg_getval(cfg, CFG_ALLOW_GROUPS).strings;
	    v != NULL && *v != NULL; v++, i++)
		;
	if ((allow_gids = malloc(sizeof(gid_t) * (i + 1))) == NULL)
		err(EXIT_FAILURE, "malloc()");

	for (i = 0, v = dsbcfg_getval(cfg, CFG_ALLOW_GROUPS).strings;
	    v != NULL && *v != NULL; v++, i++) {
		if ((gr = getgrnam(*v)) == NULL)
			errx(EXIT_FAILURE, "Unknown group '%s'", *v);
		allow_gids[i] = gr->gr_gid;
	}
	endgrent();
	allow_gids[i] = (gid_t)-1;

	spoll = dsbcfg_getval(cfg, CFG_POLL_INTERVAL).integer / 1000000;
	upoll = dsbcfg_getval(cfg, CFG_POLL_INTERVAL).integer % 1000000;

	for (i = 0; i < NFSTYPES; i++) {
		switch (fstype[i].id) {
		case UFS:
			fstype[i].uopts  = dsbcfg_getval(cfg,
			    CFG_UFS_OPTS).string;
			fstype[i].mntcmd = dsbcfg_getval(cfg,
			    CFG_UFS_MNTCMD).string;
			break;
		case CD9660:
			fstype[i].uopts  = dsbcfg_getval(cfg,
			    CFG_CD9660_OPTS).string;
			fstype[i].mntcmd = dsbcfg_getval(cfg,
			    CFG_CD9660_MNTCMD).string;
			break;
		case MSDOSFS:
			fstype[i].uopts  = dsbcfg_getval(cfg,
			    CFG_MSDOSFS_OPTS).string;
			fstype[i].mntcmd = dsbcfg_getval(cfg,
			    CFG_MSDOSFS_MNTCMD).string;
			break;
		case NTFS:
			fstype[i].uopts  = dsbcfg_getval(cfg,
			    CFG_NTFS_OPTS).string;
			fstype[i].mntcmd = dsbcfg_getval(cfg,
			    CFG_NTFS_MNTCMD).string;
			break;
		case EXT:
			fstype[i].uopts  = dsbcfg_getval(cfg,
			    CFG_EXT_OPTS).string;
			fstype[i].mntcmd = dsbcfg_getval(cfg,
			    CFG_EXT_MNTCMD).string;
			break;
		case EXFAT:
			fstype[i].uopts  = dsbcfg_getval(cfg,
			    CFG_EXFAT_OPTS).string;
			fstype[i].mntcmd = dsbcfg_getval(cfg,
			    CFG_EXFAT_MNTCMD).string;
			break;
		case REISERFS:
			fstype[i].uopts  = dsbcfg_getval(cfg,
			    CFG_REISERFS_OPTS).string;
			fstype[i].mntcmd = dsbcfg_getval(cfg,
			    CFG_REISERFS_MNTCMD).string;
			break;
		case XFS:
			fstype[i].uopts  = dsbcfg_getval(cfg,
			    CFG_XFS_OPTS).string;
			fstype[i].mntcmd = dsbcfg_getval(cfg,
			    CFG_XFS_MNTCMD).string;
			break;
		default:
			/* Just to soothe clang. */
			break;
		}
	}

	/* Ready to deamonize. */
	if (!fflag) {
		for (i = 0; i < 2; i++) {
			switch (fork()) {
			case -1:
				err(EXIT_FAILURE, "fork()");
			case  0:
				break;
			default:
				exit(EXIT_SUCCESS);
			}
			if (i == 0) {
				(void)setsid();
				(void)signal(SIGHUP, SIG_IGN);
			}
		}
		/* Write our PID to the PID/lock file. */
		(void)fprintf(fp, "%d", getpid());
		(void)fflush(fp);
		
		/* Close all files except for the PID/lock file. */
		for (i = 0; i < 16; i++) {
			/* Do not close our lockfile. */
			if (fileno(fp) != i)
				(void)close(i);
		}
		/* Redirect error messages to logfile. */
		if ((fp = fopen(PATH_DSBMD_LOG, "a+")) == NULL)
			err(EXIT_FAILURE, "fopen()");
		(void)setvbuf(fp, NULL, _IOLBF, 0);
		err_set_file(fp);
	}	
	(void)signal(SIGINT, cleanup);
	(void)signal(SIGTERM, cleanup);
	(void)signal(SIGQUIT, cleanup);
	(void)signal(SIGHUP, cleanup);
	(void)signal(SIGPIPE, SIG_IGN);

	logprintx("%s started", PROGRAM);

	/* Get all currently installed disks. */
	if (chdir(_PATH_DEV) == -1)
		err(EXIT_FAILURE, "chdir(%s)", _PATH_DEV);
	if ((dirp = opendir(".")) == NULL)
		err(EXIT_FAILURE, "opendir(%s)", _PATH_DEV);
	while ((dp = readdir(dirp)) != NULL) {
		if (lstat(dp->d_name, &sb) == -1) {
			logprint("stat(%s)", dp->d_name);
			continue;
		} else if (S_ISLNK(sb.st_mode)) { 
			/* Skip symlinks */
			continue;
		} else if (S_ISDIR(sb.st_mode) &&
		    strcmp(dp->d_name, "linux_lvm") == 0) {
			/* Get Linux Logical Volumes */
			dirp2 = opendir(dp->d_name);
			if (dirp2 == NULL)
				continue;
			while ((dp2 = readdir(dirp2)) != NULL) {
				if (strcmp(dp2->d_name, ".")  == 0 ||
				    strcmp(dp2->d_name, "..") == 0)
					continue;
				(void)snprintf(lvmpath, sizeof(lvmpath),
				    "%s/%s", dp->d_name, dp2->d_name);
				add_drive(lvmpath);
			}
			(void)closedir(dirp2);
		} else
			add_drive(dp->d_name);
	}
	(void)closedir(dirp);
	if (chdir("/") == -1)
		err(EXIT_FAILURE, "chdir(/)");
	/* Connect to devd. */
	if ((s = uconnect(PATH_DEVD_SOCKET)) == NULL)
		err(EXIT_FAILURE, "Couldn't connect to %s", PATH_DEVD_SOCKET);
	(void)pthread_mutex_init(&drv_mtx, NULL);
	(void)pthread_mutex_init(&cli_mtx, NULL);

	/* Open the listening socket for the clients. */
        (void)unlink(PATH_DSBMD_SOCKET);
	if ((ls = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1)
		err(EXIT_FAILURE, "socket()");
	(void)memset((char *)&s_addr, 0, sizeof(s_addr));
	(void)memcpy(s_addr.sun_path, PATH_DSBMD_SOCKET,
	    strlen(PATH_DSBMD_SOCKET));
	s_addr.sun_family = AF_LOCAL;
	if (bind(ls, (struct sockaddr *)&s_addr, sizeof(s_addr)) == -1)
		err(EXIT_FAILURE, "bind()");
	if (chmod(PATH_DSBMD_SOCKET, SOCKET_MODE) == -1)
		err(EXIT_FAILURE, "chmod(%s)", PATH_DSBMD_SOCKET);
	if (listen(ls, dsbcfg_getval(cfg, CFG_MAX_CLIENTS).integer) == -1)
		err(EXIT_FAILURE, "listen()");
	/*
	 * Make the listening socket non blocking in order to protect the
	 * server from certain DoS attacks.
	 */
	if ((sflags = fcntl(ls, F_GETFL)) == -1)
		err(EXIT_FAILURE, "fcntl()");
	sflags |= O_NONBLOCK;
	if (fcntl(ls, F_SETFL, sflags) == -1)
		err(EXIT_FAILURE, "fcntl()");
	maxfd = fileno(s) > ls ? fileno(s) : ls;
	FD_ZERO(&allset);
	FD_SET(ls, &allset); FD_SET(fileno(s), &allset);

	/* Start thread that checks the mount table for changes. */
	if (pthread_create(&thr, NULL, thr_check_mntbl, NULL) == 0)
		(void)pthread_detach(thr);

	/* Main loop. */
	for (;;) {
		rset = allset;
		tv.tv_sec = spoll; tv.tv_usec = upoll;

		switch (select(maxfd + 1, &rset, NULL, NULL, &tv)) {
		case -1:
			if (errno == EINTR)
				continue;
			err(EXIT_FAILURE, "select()");
			/* NOTREACHED */
		case 0:
			/* Timeout -> Poll devices. */
			while ((drvp = media_changed()) != NULL)
				update_drive(drvp);
			if (s == NULL) {
				/* Try to reconnect to devd */
				if ((s = uconnect(PATH_DEVD_SOCKET)) != NULL) {
					maxfd = fileno(s) > ls ? fileno(s) : \
					    ls;
					FD_SET(fileno(s), &allset);
				}
			}
			continue;
		}
		if (s != NULL && FD_ISSET(fileno(s), &rset)) {
			/* New devd event. */
			while ((ev = read_devd_event(s)) != NULL)
				process_devd_event(ev);
			if (feof(s)) {
				/* Lost connection to devd. */
				FD_CLR(fileno(s), &allset);
				(void)fclose(s); s = NULL;
				logprintx("Lost connection to devd");
			}
		} 
		if (FD_ISSET(ls, &rset)) {
			/* A client has connected. */
			cs = accept(ls, (struct sockaddr *)&c_addr, &clen);
			if (cs == -1) {
				switch (errno) {
				case EINTR: case EWOULDBLOCK: case ECONNABORTED:
					continue;
				default:
					err(EXIT_FAILURE, "accept()");
				}
			}
			(void)pthread_mutex_lock(&cli_mtx);
			if ((cli = add_client(cs)) == NULL) {
				if (errno != 0)
					logprint("add_client()");
			} else {
				if (pthread_create(&thr, NULL, serve_client,
				    cli) == 0) {
					if (pthread_detach(thr))
						logprint("pthread_detach()");
				} else
					logprint("pthread_create()");
			}
			(void)pthread_mutex_unlock(&cli_mtx);
		}
	}
	/* NOTREACHED */
	return (0);
}

static void
usage()
{
	(void)fprintf(stderr, "Usage: %s [-fh]\n" \
		      "   -f: Run %s in foreground.\n", PROGRAM, PROGRAM);
	exit(1);
}

static void
cleanup(int unused)
{
	logprintx("%s exited", PROGRAM);
	cliprintbc(NULL, "I:msgtype=shutdown");
	exit(EXIT_SUCCESS);
}

static drive_t *
lookupdrv(const char *dev)
{
	int i;

	dev = devbasename(dev);
	for (i = 0; i < ndrives; i++) {
		if (strcmp(dev, devbasename(drives[i]->dev)) == 0)
			return (drives[i]);
	}
	return (NULL);
}

static client_t *
add_client(int socket)
{
	int	      n, saved_errno;
	FILE	      *sp;
	char	      **p;
	uid_t	      uid;
	gid_t	      gid, gids[24];
	client_t      **cv, *cp;
	struct group  *grp;
	struct passwd *pw;

	cp = NULL; errno = 0;
	if ((sp = fdopen(socket, "r+")) == NULL)
		goto error;
	(void)setvbuf(sp, NULL, _IOLBF, 0);
	if (getpeereid(socket, &uid, &gid) == -1 ||
	   (pw = getpwuid(uid)) == NULL)
		goto error;
	gids[0] = gid;
	for (n = 1; (grp = getgrent()) != NULL;) {
		for (p = grp->gr_mem; p != NULL && *p != NULL; p++) {
			if (strcmp(pw->pw_name, *p) == 0) {
				if (grp->gr_gid != gid)
					gids[n++] = grp->gr_gid;
				break;
			}
		}
	}
	/* Terminate GID list. */
	gids[n] = (gid_t)-1;
	endgrent();
	endpwent();

	if (!check_permission(uid, gids)) {
		(void)fprintf(sp, "E:code=%d\n", ERR_PERMISSION_DENIED);
		(void)fclose(sp);
		logprintx("Client with UID %d rejected", uid);
		return (NULL);
	}
	cv = realloc(clients, sizeof(client_t *) * (nclients + 1));
	if (cv == NULL)
		goto error;
	clients = cv;
	if ((clients[nclients] = malloc(sizeof(client_t))) == NULL)
		goto error;
	cp = clients[nclients];
	if ((cp->gids = malloc((n + 1) * sizeof(gid_t))) == NULL)
		goto error;
	(void)memcpy(cp->gids, gids, n * sizeof(gid_t));
	cp->s	= sp;
	cp->uid	= uid;
	(void)pthread_mutex_init(&cp->mtx, NULL);

	/* 
	 * Send the client the current list of mountable drives. Since we
	 * want  to  send  the up to date drive information, we must lock
	 * all devices until we are done.
	 */
	(void)pthread_mutex_lock(&drv_mtx);
	for (n = 0; n < ndrives; n++) {
		if (!drives[n]->has_media || drives[n]->fs == NULL)
			continue;
		notify(cp, drives[n], true);
	}
	/* Terminate drive list output. */
	cliprint(cp, "=");

	/*
	 * Increasing  the  nclients  variable  must happen within the lock,
	 * because  the  other  clients  don't know that this client exists.
	 * If another client modifies a drive and sends a broadcast message,
	 * this  client  won't receive it and hence, its information is out-
	 * dated.
	 */
	nclients++;
	(void)pthread_mutex_unlock(&drv_mtx);
	logprintx("Client with UID %d connected", uid);

	return (cp);
error:
	saved_errno = errno;
	if (cp != NULL)
		free(cp->gids);
	free(cp);
	if (sp != NULL)
		(void)fclose(sp);
	errno = saved_errno;
	return (NULL);
}

static void
del_client(client_t *cli)
{
	int i;

	for (i = 0; i < nclients && cli != clients[i]; i++)
		;
	if (i == nclients)
		return;
	logprintx("Client with UID %d disconnected", cli->uid);
	(void)pthread_mutex_destroy(&cli->mtx);
	(void)fclose(cli->s); free(cli->gids);
	free(cli);
	
	for (; i < nclients - 1; i++)
		clients[i] = clients[i + 1];
	nclients--;
}

static char *
read_devd_event(FILE *fp)
{
	int	      c;
	static char   *buf = NULL;
	static size_t len, sz = 0;

	if (buf == NULL) {
		if ((buf = malloc(_POSIX2_LINE_MAX)) == NULL)
			err(EXIT_FAILURE, "malloc()");
		sz = _POSIX2_LINE_MAX;
	}
	for (len = 0;;) {
		if (sz - len - 1 <= 0) {
			if ((buf = realloc(buf, sz + 64)) == NULL)
				err(EXIT_FAILURE, "realloc()");
			sz += 64;
		}
		if ((c = fgetc(fp)) == EOF) {
			if (feof(fp) || errno == EAGAIN)
				return (NULL);
			else if (errno == EINTR)
				continue;
			else
				err(EXIT_FAILURE, "fgetc()");
		}
		buf[len++] = c; buf[len] = '\0';
		if (c == '\n')
			return (buf);
	}
	/* NOTREACHED */
}

static void
process_devd_event(char *ev)
{
	drive_t *drvp;

	if (ev[0] != '!')
		return;
	parse_devd_event(ev + 1);
	if (strcmp(devdevent.system, "DEVFS") != 0 ||
	    strcmp(devdevent.subsystem, "CDEV") != 0)
		return;
	if (strcmp(devdevent.type, "CREATE") == 0) {
		(void)pthread_mutex_lock(&drv_mtx);
		add_drive(devdevent.cdev);
		(void)pthread_mutex_unlock(&drv_mtx);
	} else if (strcmp(devdevent.type, "DESTROY") == 0) {
		(void)pthread_mutex_lock(&drv_mtx);
		drvp = lookupdrv(devdevent.cdev);
		if (drvp != NULL)
			del_drive(drvp);
		(void)pthread_mutex_unlock(&drv_mtx);
	}
}

static void
parse_devd_event(char *str)
{
	char *p, *q;

	devdevent.cdev	 = "";
	devdevent.system = devdevent.subsystem = devdevent.type = "";

	for (p = str; (p = strtok(p, " \n")) != NULL; p = NULL) {
		if ((q = strchr(p, '=')) == NULL)
			continue;
		*q++ = '\0';
		if (strcmp(p, "system") == 0)
			devdevent.system = q;
		else if (strcmp(p, "subsystem") == 0)
			devdevent.subsystem = q;
		else if (strcmp(p, "type") == 0)
			devdevent.type = q;
		else if (strcmp(p, "cdev") == 0)
			devdevent.cdev = q;
	}
}

static void
add_to_pollqueue(drive_t *drv)
{
	int   i, len;
	char *p;

	for (p = drv->dev; !isdigit(*p); p++)
		;
	if (p[1] == '\0')
		len = strlen(drv->dev);
	else {
		if ((p[1] == 's' || p[1] == 'p') && isdigit(p[2])) {
			/* Do not add slices. */
			return;
		}
		len = p - drv->dev + 1;
	}
	for (i = 0; i < queuesz; i++) {
		if (strncmp(drv->dev, pollqueue[i]->dev, len) == 0)
			return;
	}
	if ((pollqueue = realloc(pollqueue,
	    sizeof(drive_t *) * (queuesz + 1))) == NULL)
		err(EXIT_FAILURE, "realloc()");
	pollqueue[queuesz] = drv;
	pollqueue[queuesz]->has_media = has_media(drv->dev);
	queuesz++;
}

static void
del_from_pollqueue(drive_t *drvp)
{
	int i;

	for (i = 0; i < queuesz &&  drvp != pollqueue[i]; i++)
		;
	if (i == queuesz)
		return;
	for (; i < queuesz - 1; i++)
		pollqueue[i] = pollqueue[i + 1];
	queuesz--;
}

static bool
has_media(const char *dev)
{
	int    fd;
	off_t  size;
	size_t blksz;

	if ((fd = open(dev, O_RDONLY | O_NONBLOCK)) == -1)
		return (false);
	size  = g_mediasize(fd);
	blksz = g_sectorsize(fd);
	(void)close(fd);
	errno = 0;
	if ((int)size == -blksz || (int)size == -1)
		return (false);
	return (true);
}

/*
 * Return a pointer to the next drive whose media changed.
 */
static drive_t *
media_changed()
{
	drive_t	   *drvp;
	static int i = 0;

	for (i = i >= queuesz ? 0 : i; i < queuesz; i++) {
		if (has_media(pollqueue[i]->dev)) {
			if (!pollqueue[i]->has_media) {
				/* Media was inserted */
				pollqueue[i]->has_media = true;
				return (pollqueue[i++]);
			}
		} else { /* No media */
			if (errno == ENOENT) {
				/* Lost device */
				logprint("Lost %s", pollqueue[i]->dev);
				(void)pthread_mutex_lock(&drv_mtx);
				drvp = lookupdrv(pollqueue[i]->dev);
				if (drvp != NULL)
					del_drive(drvp);
				(void)pthread_mutex_unlock(&drv_mtx);
				i = 0;
				return (NULL);
			}
			if (pollqueue[i]->has_media) {
				/* Media was removed */
				pollqueue[i]->has_media = false;
				return (pollqueue[i++]);
			}
		}
	}
	return (NULL);
}

static void
update_drive(drive_t *drvp)
{
	char *p;

	if (drvp->has_media) {
		(void)pthread_mutex_lock(&drvp->mtx);
		drvp->dt = get_disktype(drvp->dev, drvp->dc);
		drvp->fs = getfs(drvp->dev);

		if (drvp->dt->dt_type == CDR_TYPE_DATA	 ||
		    drvp->dt->dt_type == DSK_TYPE_FLOPPY ||
		    drvp->dc->class == MSD) {
			if (drvp->fs == NULL) {
				/*
				 * A filesystem is mandatory for the above
				 * disk types.
				 */
				(void)pthread_mutex_unlock(&drvp->mtx);
				return;
			}
		}
		free(drvp->name); drvp->name = NULL;
		if (drvp->fs != NULL) {
			p = get_label(drvp->dev, drvp->fs->name);
			if (p != NULL) {
				if ((drvp->name = strdup(p)) == NULL)
					err(EXIT_FAILURE, "strdup()");
			} else {
				drvp->name = strdup(devbasename(drvp->dev));
				if (drvp->name == NULL)
					err(EXIT_FAILURE, "strdup()");
			}
		}
		if (drvp->dt->dt_type != CDR_TYPE_UNKNOWN)
			notifybc(drvp, true);
		(void)pthread_mutex_unlock(&drvp->mtx);
	} else if (drvp->fs != NULL || (drvp->dc->class == CDROM &&
	     drvp->dt->dt_type != CDR_TYPE_UNKNOWN))
		notifybc(drvp, false);
}

/*
 * Check if the given device name matches the name of a (sliced) partitioned
 * disk. If len == 0, return 'true' only if there is an exact match. If len
 * is > 0, return 'true' if 'dev' matches at least 'len' chars.
 */

static bool
match_part_dev(const char *dev, size_t len)
{
	size_t slen, maxlen;
	struct gmesh     mesh;
	struct ggeom     *gp;
	struct gclass    *cp;
	struct gprovider *pp;

	maxlen = 0;

	if (geom_gettree(&mesh) != 0)
		return (false);
	LIST_FOREACH(cp, &mesh.lg_class, lg_class) {
		if (strcmp(cp->lg_name, "PART") != 0)
			continue;
		LIST_FOREACH(gp, &cp->lg_geom, lg_geom) {
			if (LIST_EMPTY(&gp->lg_provider))
				continue;
			LIST_FOREACH(pp, &gp->lg_provider, lg_provider) {
				if (len == 0)
					slen = strlen(dev);
				else
					slen = len;
				if (strncmp(pp->lg_name, dev, slen) == 0) {
					if (len > 0) {
						/* Just match substring. */
						geom_deletetree(&mesh);
						return (true);
					}
					if (maxlen < strlen(pp->lg_name))
						maxlen = strlen(pp->lg_name);
				}
                	}
		}
	}
	geom_deletetree(&mesh);
	if (len == 0 && maxlen > 0 && maxlen == strlen(dev))
		return (true);
	return (false);
}


/*
 * Take the disk part (e.g. adX) of a device name, and check if it has
 * slices or partitions.
 */
static bool
is_parted(const char *dev)
{
	size_t len = 0;
	
	dev = devbasename(dev);

	while (dev[len] != '\0' && !isdigit(dev[len]))
		len++;
	while (isdigit(dev[len]))
		len++;
	return (match_part_dev(dev, len));
}

/*
 * We consider a drive not mountable if it appears in /etc/fstab without
 * the 'noauto' option, or if it's a swap device.
 */
static bool
is_mountable(const char *dev)
{
	char	      *p, *label;
	bool	      found;
	size_t	      nmib, len;
	const char    *q;
	static int    nswap = 0, mib[4], i;
	static char   **swap = NULL;
	struct fstab  *fs;
	struct xswdev xsw;

	dev = devbasename(dev);

	/* Only accept partitions/slices if the device has them. */
	if (is_parted(dev) && !match_part_dev(dev, 0))
		return (false);
	while ((fs = getfsent()) != NULL) {
		q = devbasename(fs->fs_spec);
		for (i = 0, found = false; i < NGLBLPRFX && !found; i++) {
			label = get_geom_label(dev, glblprfx[i]);
			if (label != NULL && strcmp(q, label) == 0)
				found = true;
		}
		if (!found && strcmp(q, dev) != 0)
			continue;
		if (strcmp(fs->fs_type, FSTAB_SW) == 0 ||
		    strcmp(fs->fs_type, FSTAB_XX) == 0) {
			endfsent();
			return (false);
		}
		endfsent();
		for (p = fs->fs_mntops; (p = strtok(p, ",")) != NULL; p = NULL)
			if (strcmp(p, "noauto") == 0)
				return (true);
		return (false);
	}
	endfsent();

	/* Is it a mounted swap device? */
	if (swap == NULL) {
		/* Get a list of swap devices. */
		nmib = sizeof(mib) / sizeof(int);
		if (sysctlnametomib("vm.swap_info", mib, &nmib) == -1)
			logprint("sysctlnametomib()");
		/* Inspired by pstat */
		for (i = 0; ; i++) {
			mib[nmib] = i;
			len = sizeof(xsw);
			if (sysctl(mib, nmib + 1, &xsw, &len, NULL, 0) == -1)
				break;
			else if (xsw.xsw_dev != NODEV) {
				swap = extend_list(swap, &nswap,
				    devname(xsw.xsw_dev, S_IFCHR));
			}
		}
	}
	for (i = 0; i < nswap; i++) {
		if (strcmp(dev, swap[i]) == 0)
			return (false);
	}
	return (true);
}

/*
 * Extends the given iovec list with the name-val pair, and terminates the list
 * with a NULL pointer. The new list lenght (old lenght + 2) will be returned.
 */
static int
extend_iovec(struct iovec **iov, int *iovlen, const char *name, const char *val)
{
	int	     n;
	struct iovec *v;

	n = *iovlen + 2 + 1;

	if ((v = realloc(*iov, sizeof(struct iovec) * n)) == NULL)
		return (-1);
	if ((v[n - 3].iov_base = strdup(name)) == NULL)
		return (-1);
	v[n - 3].iov_len  = strlen(name) + 1;
	if ((v[n - 2].iov_base = strdup(val)) == NULL)
		return (-1);
	v[n - 2].iov_len  = strlen(val) + 1;
	/* Mark end of array */
	v[n - 1].iov_base = NULL;

	*iov	= v;
	*iovlen = n - 1;

 	return (*iovlen);
}

static void
free_iovec(struct iovec *iov)
{
	int i, saved_errno;

	saved_errno = errno;
	for (i = 0; iov[i].iov_base != NULL; i++)
		free(iov[i].iov_base);
	free(iov);
	errno = saved_errno;
}

/*
 * Check whether vfs.usermount is set.
 */
static bool
usermount_set()
{
	int    v;
	size_t sz = sizeof(int);

	if (sysctlbyname("vfs.usermount", &v, &sz, NULL, 0) == -1) {
		logprint("sysctlbyname()");
		return (false);
	}
	return (v != 0 ? true : false);
}

static void
switcheids(uid_t euid, gid_t egid)
{
	if (setegid(egid) == -1)
		logprint("setegid(%u)", egid);
	if (seteuid(euid) == -1)
		logprint("seteuid(%u)", euid);
}

static void
restoreids()
{
	switcheids(getuid(), getgid());
}

static int
set_msdosfs_locale(const char *locale, struct iovec **iov, int *iovlen)
{
	const char *cs;

	if (modfind("msdosfs_iconv") == -1) {
		if (errno != ENOENT) {
			logprint("modfind(msdosfs_iconv) failed.");
			return (-1);
		}
		if (kldload("msdosfs_iconv") == -1 && errno != EEXIST) {
			logprint("kldload(msdosfs_iconv)");
			return (-1);
		}
	}
	if ((cs = strchr(locale, '.')) == NULL) {
		logprintx("Invalid locale string '%s'", locale);
		return (-1);
	}
	locale = kiconv_quirkcs(cs + 1, KICONV_VENDOR_MICSFT);
	if (extend_iovec(iov, iovlen, "cs_win", ENCODING_UNICODE) == -1 ||
	    extend_iovec(iov, iovlen, "cs_local", locale) == -1		||
	    extend_iovec(iov, iovlen, "cs_dos", locale) == -1		||
	    extend_iovec(iov, iovlen, "kiconv", "") == -1)
		err(EXIT_FAILURE, "extend_iovec()");
	(void)kiconv_add_xlat16_cspair(locale, locale,
	    KICONV_FROM_UPPER | KICONV_LOWER);

	return (0);
}

static int
mymount(const char *fs, const char *dir, const char *dev, const char *opts,
	uid_t uid, gid_t gid)
{
	int	     iovlen, ret;
	char	     *p, *op, *q;
	struct iovec *iov;

	iov = NULL; iovlen = 0;
	if (extend_iovec(&iov, &iovlen, "fstype", fs) == -1  ||
	    extend_iovec(&iov, &iovlen, "fspath", dir) == -1 ||
	    extend_iovec(&iov, &iovlen, "from", dev) == -1) 
		err(EXIT_FAILURE, "extend_iovec()");
	if (opts != NULL) {
		if ((op = strdup(opts)) == NULL)
			err(EXIT_FAILURE, "strdup()");
		for (p = op; (p = strtok(p, ",")) != NULL; p = NULL) {
			if ((q = strchr(p, '=')) == NULL)
				q = "";
			else
				*q++ = '\0';
			if (extend_iovec(&iov, &iovlen, p, q) == -1)
				err(EXIT_FAILURE, "extend_iovec()");
		}
		free(op);
	}
	if (strcmp(fs, "msdosfs") == 0 &&
	    dsbcfg_getval(cfg, CFG_MSDOSFS_LOCALE).string != NULL) {
		if (set_msdosfs_locale(
		    dsbcfg_getval(cfg, CFG_MSDOSFS_LOCALE).string,
		    &iov, &iovlen) == -1)
			logprintx("set_msdosfs_locale() failed.");
	}
	errno = 0;

	/* Mount as user if "usermount" and vfs.usermount is set */
	if (dsbcfg_getval(cfg, CFG_USERMOUNT).boolean && usermount_set())
		switcheids(uid, gid);
	ret = nmount(iov, iovlen, 0);
	restoreids();
	free_iovec(iov);

	return (ret);
}

static bool
check_permission(uid_t uid, gid_t *gids)
{
	int   i;
	uid_t *up;
	gid_t *gp;

	for (up = allow_uids; up != NULL && *up != (uid_t)-1; up++) {
		if (uid == *up)
			return (true);
	}
	for (gp = allow_gids; gp != NULL && *gp != (gid_t)-1; gp++) {
		for (i = 0; gids[i] != (gid_t)-1; i++) {
			if (gids[i] == *gp)
				return (true);
		}
	}
	return (false);
}

static int
mount_drive(client_t *cli, drive_t *drvp)
{
	int	    error = 0, i, j, len;
	bool	    have_mntpt = false;
	char	    mopts[512], romopts[512], num[12], *mntpath, *p, *q;
	mode_t	    mode;
	const char  *op;
	struct stat sb;

	if (!drvp->has_media) {
		cliprint(cli, "E:command=mount:code=%d", ERR_NO_MEDIA);
		return (ERR_NO_MEDIA);
	}
	if (drvp->fs == NULL) {
		cliprint(cli, "E:command=mount:code=%d",
		    ERR_UNKNOWN_FILESYSTEM);
		return (ERR_UNKNOWN_FILESYSTEM);
	}
	if (drvp->fs->uopts != NULL)
		op = drvp->fs->uopts;
	else
		op = drvp->fs->dopts;
	/* Resolve field codes. */
	len = sizeof(mopts) - 1;
	for (i = 0; i < len && op != NULL && *op != '\0'; op++) {
		if (op[0] == '%') {
			switch (op[1]) {
			case '%': /* % */
				mopts[i++] = *op++;
				break;
			case 'u': /* GID */
			case 'g': /* UID */
				/* FALLTHROUGH */
				(void)snprintf(num, sizeof(num), "%d",
				    op[1] == 'u' ? cli->uid : cli->gids[0]);
				for (j = 0; num[j] != '\0' && i < len; j++)
					mopts[i++] = num[j];
				op++;
				break;
			}
		} else
			mopts[i++] = *op;
	}
	mopts[i] = '\0';

	/* Create an alternative mount option list for read-only mounts. */
	(void)strcpy(romopts, mopts);
	for (p = romopts; (q = strchr(p, ',')) != NULL; p = q + 1) {
		if (p[0] == 'r' && p[1] == 'w' && (p[2] == ',' || p[2] == '\0'))
			p[1] = 'o';
	}
	if (strcmp(romopts, mopts) == 0) {
		/* Append ro-flag */
		p = romopts; q = strchr(p, '\0');
		(void)strncat(romopts, ",ro", sizeof(romopts) - (q - p) - 1);
	}

	/* Check if the drive is already mounted. */
	if ((drvp->mounted && drvp->fs->mntcmd) || getmntpt(drvp) != NULL) {
		cliprint(cli, "E:command=mount:code=%d", ERR_ALREADY_MOUNTED);
		return (ERR_ALREADY_MOUNTED);
	}

	/* Create the mount point */
	if (dsbcfg_getval(cfg, CFG_MNTDIR).string == NULL)
		errx(EXIT_FAILURE, "mount_dir undefined");
	if (mkdir(dsbcfg_getval(cfg, CFG_MNTDIR).string, MNTDIRPERM) == -1) {
		if (errno != EEXIST)
			err(EXIT_FAILURE, "mkdir(%s)",
			    dsbcfg_getval(cfg, CFG_MNTDIR).string);
	}
	mntpath = malloc(strlen(dsbcfg_getval(cfg, CFG_MNTDIR).string) +
	    strlen(drvp->name) + 2);
	if (mntpath == NULL)
		err(EXIT_FAILURE, "malloc()");
	/* Skip directory part in case of Linux LV */
	if ((p = strchr(drvp->name, '/')) != NULL)
		p++;
	else
		p = drvp->name;
	(void)sprintf(mntpath, "%s/%s", dsbcfg_getval(cfg, CFG_MNTDIR).string,
	    p);

	/* Mode for the mount point: rwx r-x r-x */
	mode = (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);

	if (stat(mntpath, &sb) == -1 && errno != ENOENT)
		err(EXIT_FAILURE, "stat(%s)", mntpath);
	else if (errno == ENOENT) {
		if (mkdir(mntpath, mode) == -1)
			err(EXIT_FAILURE, "mkdir(%s)", mntpath);
	} else {
		/* 
		 * File exists.  If  the  file  isn't  a  directory, or a
		 * directory  which  is  not  empty,  or  if there is any
		 * other reason why we can't delete the directory, try to
		 * create an alternative mount point.
		 */		
		if (!S_ISDIR(sb.st_mode) || rmdir(mntpath) == -1) {
			free(mntpath);
			if ((mntpath = malloc(MNAMELEN)) == NULL)
				err(EXIT_FAILURE, "malloc()");
			if (strcmp(devbasename(drvp->dev), drvp->name) != 0) {
				/*
				 * If  the  device's  devname is != its vol ID
				 * try   to   create   a   mount   path   with
				 * <mntdir>/<devname>. If that also fails, try
				 * to create a random mount path.
				 */
				(void)snprintf(mntpath, MNAMELEN, "%s/%s",
				    dsbcfg_getval(cfg, CFG_MNTDIR).string,
				    devbasename(drvp->dev));
				if (mkdir(mntpath, mode) == -1) {
					if (errno != EEXIST)
						err(EXIT_FAILURE, "mkdir(%s)",
						    mntpath);
					/* Dir exists. */
					have_mntpt = false;
				} else
					have_mntpt = true; /* Yay! */
			}
			if (!have_mntpt) {
				/*
				 * No luck so far. Create a random mount
				 * point
				 */
				(void)snprintf(mntpath, MNAMELEN, "%s/%s.XXXX",
				    dsbcfg_getval(cfg, CFG_MNTDIR).string,
				    devbasename(drvp->dev));
				if (mkdtemp(mntpath) == NULL) {
					err(EXIT_FAILURE, "mkdtemp(%s)",
					    mntpath);
				}
			}
		} else {
			/* Recreate directory */
			if (mkdir(mntpath, mode) == -1)
				err(EXIT_FAILURE, "mkdir(%s)", mntpath);
		}
	}
	if (chown(mntpath, cli->uid, cli->gids[0]) == -1)
		err(EXIT_FAILURE, "chown(%s)", mntpath);
	errno = 0;

	if (drvp->fs->mntcmd != NULL) {
		/*
		 * Execute the userdefined mount command.
		 */
	
		/* Mount as user if "usermount" and vfs.usermount is set */
		if (dsbcfg_getval(cfg, CFG_USERMOUNT).boolean &&
		    usermount_set())
			switcheids(cli->uid, cli->gids[0]);
		(void)snprintf(num, sizeof(num), "%u", cli->uid);
		(void)setenv(ENV_UID, num, 1);
		(void)snprintf(num, sizeof(num), "%u", cli->gids[0]);
		(void)setenv(ENV_GID, num, 1);
		(void)setenv(ENV_DEV, drvp->dev, 1);
		(void)setenv(ENV_LABEL, drvp->name, 1);
		(void)setenv(ENV_FILESYSTEM, drvp->fs->name, 1);
		(void)setenv(ENV_MNTPT, mntpath, 1);

		if ((error = system(drvp->fs->mntcmd)) == 0 &&
		    !is_mntpt(mntpath)) {
			cliprint(cli, "E:command=mount:code=%d",
			    ERR_UNKNOWN_ERROR);
			logprintx("Command '%s' executed by UID %d returned " \
			    "0, but the mount point %s could not be found " \
			    "in the mount table", drvp->fs->mntcmd, cli->uid,
			    mntpath);
		} else if (is_mntpt(mntpath)) {
			drvp->mntpt = mntpath;
			drvp->mounted = true;
			cliprint(cli, "O:command=mount:dev=%s:mntpt=%s",
			    drvp->dev, drvp->mntpt);
			cliprintbc(cli, "I:msgtype=mount:dev=%s:mntpt=%s",
			    drvp->dev, drvp->mntpt);
			logprintx("Device %s mounted on %s by UID %d",
			    drvp->dev, drvp->mntpt, cli->uid);
		} else {
			cliprint(cli, "E:command=mount:code=%d:mntcmderr=%d",
			    ERR_MNTCMD_FAILED, error);
			if (errno != 0) {
				logprint("Command %s executed by UID %d " \
				    "failed with code %d", drvp->fs->mntcmd,
				    cli->uid, error);
			} else {
				logprintx("Command %s executed by UID %d " \
                                    "failed with code %d", drvp->fs->mntcmd,
                                    cli->uid, error);
			}
		}
		restoreids();
		return (error);
	}
	if (!mymount(drvp->fs->name, mntpath, drvp->dev, mopts, cli->uid,
	    cli->gids[0]) ||
	    !mymount(drvp->fs->name, mntpath, drvp->dev, romopts, cli->uid,
	    cli->gids[0])) {
		free(mntpath);
		if (getmntpt(drvp) == NULL)
			err(EXIT_FAILURE, "getmntpt()");
		drvp->mounted = true;
		cliprint(cli, "O:command=mount:dev=%s:mntpt=%s",
		    drvp->dev, drvp->mntpt);
		cliprintbc(cli, "I:msgtype=mount:dev=%s:mntpt=%s",
		    drvp->dev, drvp->mntpt);
		logprintx("Device %s mounted on %s by UID %d", drvp->dev,
		    drvp->mntpt, cli->uid);
		return (0);
	}
	cliprint(cli, "E:command=mount:code=%d", errno);
	logprint("Mounting of %s by UID %d failed", drvp->dev, cli->uid);
	free(mntpath);
	return (error);
}

/*
 * Unmounts a drive. If 'force'  is  true, unmounting of the drive will be
 * enforced,  even  if  the  drive is busy. If 'eject' is true, no command
 * reply  code  will  be send to the client. This is used for eject_media()
 * to prevent dsbmd  from sending two reply codes (one for unmount, and one
 * for eject) to the client.
 */
static int
unmount_drive(client_t *cli, drive_t *drvp, bool force, bool eject)
{

	if (drvp->dc->class != FUSE &&
	    (!drvp->mounted && drvp->fs->mntcmd != NULL) &&
	    getmntpt(drvp) == NULL) {
		if (!eject) {
			cliprint(cli, "E:command=unmount:code=%d",
			    ERR_NOT_MOUNTED);
		}
		return (ERR_NOT_MOUNTED);
	}
	if (unmount(drvp->mntpt, force ? MNT_FORCE : 0) == -1) {
		if (errno == EINVAL) {
			/* Not mounted. */
			if (!eject) {
				cliprint(cli, "E:command=unmount:code=%d",
				    ERR_NOT_MOUNTED);
			}
			return (ERR_NOT_MOUNTED);
		}
		if (!eject)
			cliprint(cli, "E:command=unmount:code=%d", errno);
		logprint("Unmounting of %s mounted on %s by UID %d " \
		    "failed", drvp->dev, drvp->mntpt, cli->uid);
		return (errno);
	}
	/* Unmounting was successfull. */
	if (!eject) {
		cliprint(cli, "O:command=unmount:dev=%s:mntpt=%s", drvp->dev,
		    drvp->mntpt);
	}
	/*
	 * If a device is mounted and the client sent an eject command, it
	 * could happen that the unmount was successful, but ejecting failed.
	 * With some devices, CAM reports ejecting the media was successful,
	 * albeit it wasn't. So in case unmounting was initiated by the eject
	 * command, we send the client an info message informing them that the
	 * device was unmounted.
	 */
	cliprintbc(eject ? NULL : cli, "I:msgtype=unmount:dev=%s:mntpt=%s",
	    drvp->dev, drvp->mntpt);
	logprintx("Device %s unmounted from %s by UID %d", drvp->dev,
	    drvp->mntpt, cli->uid);
	rmntpt(drvp->mntpt);
	free(drvp->mntpt); drvp->mntpt = NULL;
	drvp->mounted = false;
	if (drvp->dc->class == FUSE)
		del_drive(drvp);
	sleep(1);
	return (0);
}

/*
 * Looks up the given drive's mount point in the mount table.
 */
static char *
getmntpt(drive_t *drvp)
{
	int	      i, j, n;
	const char    *p, *q, *g;
	struct statfs *mb;

	errno = 0;
	if ((n = getmntinfo(&mb, MNT_WAIT)) == -1)
		err(EXIT_FAILURE, "getmntinfo()");
	p = devbasename(drvp->dev);
	for (i = 0; i < n; i++) {
		q = devbasename(mb[i].f_mntfromname);
		if (strcmp(p, q) == 0) {
			/* The drive was mounted using its device name. */
			if (drvp->mntpt != NULL &&
			    strcmp(drvp->mntpt, mb[i].f_mntonname) == 0)
				return (drvp->mntpt);
			free(drvp->mntpt);
			if ((drvp->mntpt = strdup(mb[i].f_mntonname)) == NULL)
				err(EXIT_FAILURE, "strdup()");
			return (drvp->mntpt);
		}
		/* Check if the drive was mounted using its glabel. */
		for (j = 0; j < NGLBLPRFX && drvp->glabel[j] != NULL; j++) {
			/* Skip the glabel-prefix (ufs/, cd9660/, etc.). */
			if ((g = strchr(drvp->glabel[j], '/')) != NULL)
				g++;
			else
				g = drvp->glabel[j];
			if (strcmp(drvp->glabel[j], q) == 0 ||
			    strcmp(g, q) == 0) {
				if (drvp->mntpt != NULL &&
				    strcmp(drvp->mntpt, mb[i].f_mntonname) == 0)
					return (drvp->mntpt);
				free(drvp->mntpt);
				if ((drvp->mntpt =
				    strdup(mb[i].f_mntonname)) == NULL)
					err(EXIT_FAILURE, "strdup()");
				return (drvp->mntpt);
			}
		}
	}
	return (NULL);
}

/*
 * Removes the given mount point path if it's under CFG_MNTDIR (/media)
 */
static void
rmntpt(const char *path)
{
	char	   rpath[PATH_MAX];
	const char *mntprfx, *p;

	mntprfx = dsbcfg_getval(cfg, CFG_MNTDIR).string;

	/* Skip leading '/' */
	while (mntprfx[1] == '/')
		mntprfx++;
	/* Skip trailing '/' */
	for (p = strchr(mntprfx, '\0') - 1; p != mntprfx && *p == '/'; p--)
		;
	if ((path = realpath(path, rpath)) == NULL)
		return;
	if (strncmp(path, mntprfx, p - mntprfx + 1) == 0 &&
	    path[p - mntprfx + 1] == '/') {
		path += (p - mntprfx + 1) + 1;
		if (strlen(path) == 0)
			return;
		(void)rmdir(rpath);
	}
}

/*
 * Checks whether 'path' is a mount point.
 */
static bool
is_mntpt(const char *path)
{
	int	       i, n;
	struct statfs *mb;

	errno = 0;
	if ((n = getmntinfo(&mb, MNT_WAIT)) == -1)
		err(EXIT_FAILURE, "getmntinfo()");
	for (i = 0; i < n && path != NULL; i++) {
		if (strcmp(path, mb[i].f_mntonname) == 0)
			return (true);
	}
	return (false);
}

static char **
extend_list(char **list, int *size, const char *str)
{
	if ((list = realloc(list, (*size + 1) * sizeof(char *))) == NULL) {
		logprint("realloc()");
		return (NULL);
	}
	if ((list[*size] = strdup(str)) == NULL) {
		logprint("strdup()");
		return (NULL);
	}
	(*size)++;

	return (list);
}	

/*
 * Returns the path of a device without the slice part.
 */
static char *
get_diskname(const char *path)
{
	static char   *p, *name = NULL;
	static size_t  len = 0;

	if (len < strlen(path)) {
		len = strlen(path) + 10;
		if ((name = realloc(name, len)) == NULL)
			err(EXIT_FAILURE, "realloc()");
	}
	for (p = name; !isdigit(*path) && *path != '\0'; *p++ = *path++)
		;
	while (isdigit(*path))
		*p++ = *path++;
	*p = '\0';
	return (name);
}

/*
 * Determines the CDROM/DVD type of a given CD/DVD device.
 */
static int
get_cdrtype(const char *path)
{
	int	fd, lbs, seqnum, dirtblpos, dirtblsz, type, reclen;
	int	i, len, sector, offset, saved_errno, namelen, pbs;
	char	*buf, *p;
	bool	has_video_ts, has_mpeg2, has_mpegav, has_svcd, has_vcd;
	off_t	msz;
	struct ioc_toc_header tochdr;
        struct iso_directory_record *dp;
	struct iso_primary_descriptor *ip;
	struct ioc_read_toc_single_entry tocent;

	if (!has_media(path))
		return (CDR_TYPE_UNKNOWN);
	buf = NULL; type = CDR_TYPE_UNKNOWN;
	if ((fd = open(path, O_RDONLY)) == -1) {
		logprint("open()");
		goto error;
	}
	/* Check whether the drive has a valid media. */
	if (ioctl(fd, DIOCGMEDIASIZE, &msz) == -1 || msz <= 0) {
		logprint("mediasize");
		goto done;
	}
	/*
	 * Reopening  the device seems to be necessary after calling
	 * DIOCGMEDIASIZE. Without reopening, CDIOREADTOCHEADER will
	 * fail.
	 */
	(void)close(fd);
	if ((fd = open(path, O_RDONLY)) == -1) {
		logprint("open()");
		goto error;
	}
	if ((pbs = g_sectorsize(fd)) == -1)
		goto error;
	if (ioctl(fd, CDIOREADTOCHEADER, &tochdr) == -1)
		goto error;
	tocent.track	      = tochdr.starting_track;
	tocent.address_format = CD_LBA_FORMAT;
	if (ioctl(fd, CDIOREADTOCENTRY, &tocent) == -1) 
		goto error;
	/*
	 * If bit 2 of the 4 control bits in the subchannel Q is
	 * not set, it is probably an audio CD.
	 */
	if (!(tocent.entry.control & (1 << 2))) {
		type = CDR_TYPE_AUDIO;
		goto done;
	} else
		type = CDR_TYPE_RAW;
	sector = (ISO_DEFAULT_BLOCK_SIZE * 16) / pbs;
	offset = (ISO_DEFAULT_BLOCK_SIZE * 16) % pbs;
	if (lseek(fd, sector * pbs, SEEK_SET) == -1)
		goto error;
	if ((buf = malloc(2 * pbs)) == NULL)
		goto error;
	if (read(fd, buf, pbs) == -1)
		goto error;
	p  = buf + offset;
	ip = (struct iso_primary_descriptor *)p;
	if (strncmp(ip->id, ISO_STANDARD_ID, sizeof(ISO_STANDARD_ID) - 1))
		/* No ISO9660 filesystem */
		goto done;
	type = CDR_TYPE_DATA;
	dp = (struct iso_directory_record *)ip->root_directory_record;

	lbs	  = isonum_723((u_char *)ip->logical_block_size);
	seqnum    = isonum_723((u_char *)dp->volume_sequence_number);
	dirtblsz  = isonum_733((u_char *)dp->size);
	dirtblpos = isonum_733((u_char *)dp->extent);

	sector = (lbs * dirtblpos) / pbs;
	offset = (lbs * dirtblpos) % pbs;
	if (lseek(fd, sector * pbs, SEEK_SET) == (off_t)-1)
		goto error;
	if (read(fd, buf, pbs) == -1)
		goto error;
	p   = buf + offset;
	len = pbs - offset;
	has_video_ts = has_mpeg2 = has_mpegav = has_svcd = has_vcd = false;
	while (type == CDR_TYPE_DATA && dirtblsz > 0) {
		if (len <= ISO_DIRECTORY_RECORD_SIZE + 31) {
			for (i = 0; i < len; i++)
				buf[i] = *p++;
			p = buf;
			if (read(fd, buf + len, pbs) == -1)
				goto error;
			len += pbs;
		}
		dp     = (struct iso_directory_record *)p;
		reclen = (u_int)dp->length[0];
		if (isonum_723((u_char *)dp->volume_sequence_number) != seqnum)
			break;
		if (((u_char)dp->flags[0] & (1 << 1))) {
			/* Directory */
			namelen = (u_int)dp->name_len[0] > 31 ? 31 : \
			    (u_int)dp->name_len[0];
			if (!strncasecmp(dp->name, "video_ts", namelen))
				has_video_ts = true;
			else if (!strncasecmp(dp->name, "VCD", namelen))
				has_vcd = true;
			else if (!strncasecmp(dp->name, "SVCD", namelen))
				has_svcd = true;
			else if (!strncasecmp(dp->name, "MPEGAV", namelen))
				has_mpegav = true;
			else if (!strncasecmp(dp->name, "MPEG2", namelen))
				has_mpeg2 = true;
		}
		if (has_video_ts)
			type = CDR_TYPE_DVD;
		else if (has_mpeg2 && has_svcd)
			type = CDR_TYPE_SVCD;
		else if (has_mpegav && has_vcd)
			type = CDR_TYPE_VCD;
		p	 += reclen;
		len	 -= reclen;
		dirtblsz -= reclen;
	}
done:	free(buf);
	(void)close(fd);
	return (type);

error:	saved_errno = errno;
	free(buf);
	(void)close(fd);
	errno = saved_errno;
	return (-1);
}

/*
 * Looks up the disktype object in the disktypes table and returns a
 * pointer to it.
 */
static const dsktp_t *
lookup_disktype(int type)
{
	int i;

	for (i = 0; i < sizeof(disktypes) / sizeof(dsktp_t); i++) {
		if (type == disktypes[i].dt_type)
			return (&disktypes[i]);
	}
	return (NULL);
}

/*
 * Determines the type (hard drive, audio CD, SVCD, etc.) of a drive.
 */
static const dsktp_t *
get_disktype(const char *dev, const dskcl_t *dc)
{
	int  type;
	char *disk;
	struct cam_device *cd;

	if (dc->class == CDROM) {
		if ((type = get_cdrtype(dev)) == -1) {
			logprint("get_cdrtype()");
			return (lookup_disktype(CDR_TYPE_UNKNOWN));
		}
		return (lookup_disktype(type));
	} else if (dc->class == FLOPPY)
		return (lookup_disktype(DSK_TYPE_FLOPPY));
	else if (dc->class == MMC)
		return (lookup_disktype(DSK_TYPE_MMC));
	else if (dc->system == CAM) {
		disk = get_diskname(dev);
		if ((cd = cam_open_device(disk, O_RDWR)) != NULL) {
			if (strncmp(cd->sim_name, "umass", 5) == 0) {
				cam_close_device(cd);
				return (lookup_disktype(DSK_TYPE_USBDISK));
			}
			cam_close_device(cd);
		} else
			logprint("cam_open_device(%s): %s", disk, cam_errbuf);
	}
	return (lookup_disktype(DSK_TYPE_HDD));
}

static drive_t *
add_fuse_device(const char *mntpt)
{
	int	   i;
	drive_t	   **drvp;
	const char *p;
	static int id = 0;

	drvp = realloc(drives, sizeof(drive_t *) * (ndrives + 1));
	if (drvp == NULL)
		err(EXIT_FAILURE, "realloc()");
	drives = drvp;
	if ((drives[ndrives] = malloc(sizeof(drive_t))) == NULL)
		err(EXIT_FAILURE, "malloc()");
	/* Generate a fictive device name */
	if ((drives[ndrives]->dev = strdup("/dev/pseudo##")) == NULL)
		err(EXIT_FAILURE, "strdup()");
	(void)sprintf(drives[ndrives]->dev, "/dev/pseudo%02d", id++);
	/* Use the last part of mount point path for the name */
	for (p = strchr(mntpt, '\0'); *p != '/' && p != mntpt; p--)
		;
	if (*p == '/')
		p++;
	if ((drives[ndrives]->name = strdup(p)) == NULL)
		err(EXIT_FAILURE, "strdup()");
	for (i = 0; i < NDISK_CLASSES && disk_classes[i].class != FUSE; i++)
		;
	drives[ndrives]->dc	   = &disk_classes[i];
	for (i = 0; i < NFSTYPES && fstype[i].id != FUSEFS; i++)
		;
	drives[ndrives]->fs	   = &fstype[i];
	for (i = 0;
	    i < NDISK_TYPES && disktypes[i].dt_type != DSK_TYPE_FUSE; i++)
		;
	drives[ndrives]->dt	   = &disktypes[i];
	drives[ndrives]->glabel[0] = NULL;
	drives[ndrives]->mounted   = true;
	drives[ndrives]->has_media = true;
	drives[ndrives]->polling   = false;
	drives[ndrives]->mntpt	   = strdup(mntpt);
	if (drives[ndrives]->mntpt == NULL)
		err(EXIT_FAILURE, "strdup()");
	(void)pthread_mutex_init(&drives[ndrives]->mtx, NULL);
	notifybc(drives[ndrives], true);
	return (drives[ndrives++]);

}

static drive_t *
add_drive(const char *dev)
{
	int	   len, i, j, speed, fd;
	char	   **v, *path;
	drive_t	   **drvp, drv = { 0 };
	const char *p;

	dev = devbasename(dev);
	/* Check if we already have this device. */
	len = strlen(dev);
	for (i = 0; i < ndrives; i++) {
		if (strcmp(dev, drives[i]->dev + sizeof(_PATH_DEV) - 1) == 0) {
			/* Device already exists. */
			return (NULL);
		}
	}
	if ((drv.dc = match_disk_pattern(dev)) == NULL)
		return (NULL);
	if (!is_mountable(dev))
		return (NULL);
	if (drv.dc->class == CDROM) {
		/* Ignore devices like 'acd0t01' and atapicam devices */
		for (p = strlen(dev) - 1 + dev; isdigit(*p) && p != dev; p--)
			;
		if (*p == 't')
			return (NULL);
		if (drv.dc->system == CAM && is_atapicam(dev))
			return (NULL);
	}
	path = devpath(dev);
	if ((drv.has_media = has_media(path)))
		drv.fs = getfs(path);
	else
		drv.fs = NULL;
	if (drv.dc->class == MSD && drv.has_media && drv.fs == NULL) {
		/* Mass storage device with unknown filesystem. */
		return (NULL);
	}
	drvp = realloc(drives, sizeof(drive_t *) * (ndrives + 1));
	if (drvp == NULL)
		err(EXIT_FAILURE, "realloc()");
	drives = drvp;
	if ((drives[ndrives] = malloc(sizeof(drive_t))) == NULL)
		err(EXIT_FAILURE, "malloc()");
	if ((drives[ndrives]->dev = strdup(path)) == NULL)
		err(EXIT_FAILURE, "strdup()");
	if (drv.fs != NULL && (p = get_label(dev, drv.fs->name)) != NULL) {
		if ((drives[ndrives]->name = strdup(p)) == NULL)
			err(EXIT_FAILURE, "strdup()");
	} else if ((drives[ndrives]->name = strdup(dev)) == NULL)
		err(EXIT_FAILURE, "strdup()");

	/*
	 * Get all glabels for this drive. Drives with UFS can have more than
	 * one glabel: ufs/somename, or label/somename, and ufsid/id.
	 */
	for (i = j = 0; i < NGLBLPRFX; i++) {
		if ((p = get_geom_label(dev, glblprfx[i])) != NULL) {
			if ((drives[ndrives]->glabel[j++] = strdup(p)) == NULL)
				err(EXIT_FAILURE, "strdup()");
		}
	}
	/* Terminate glabel list. */
	drives[ndrives]->glabel[j] = NULL;
	drives[ndrives]->dc	   = drv.dc;
	drives[ndrives]->fs	   = drv.fs;
	drives[ndrives]->mounted   = false;
	drives[ndrives]->mntpt	   = NULL;
	drives[ndrives]->realdev   = NULL;
	drives[ndrives]->has_media = drv.has_media;
	drives[ndrives]->speed	   = dsbcfg_getval(cfg, CFG_CDRSPEED).integer;

	/* Set max. CD/DVD reading speed. */
	if (drives[ndrives]->dc->class == CDROM) {
		speed = dsbcfg_getval(cfg, CFG_CDRSPEED).integer * 177;
		if ((fd = open(drives[ndrives]->dev, O_RDWR)) != -1) {
			if (ioctl(fd, CDRIOCREADSPEED, &speed) == -1) {
				logprint("ioctl(%s, CDRIOCREADSPEED)",
				    drives[ndrives]->dev);
			}
			(void)close(fd);
		} else
			logprint("open(%s)", drives[ndrives]->dev);
	}
	(void)pthread_mutex_init(&drives[ndrives]->mtx, NULL);

	(void)getmntpt(drives[ndrives]);
	if (drives[ndrives]->mntpt != NULL)
		drives[ndrives]->mounted = true;

	if (drives[ndrives]->dc->class == LLV) {
		if ((p = get_lv_dev(dev)) != NULL) {
			path = devpath(p);
			if ((drives[ndrives]->realdev = strdup(path)) == NULL)
				err(EXIT_FAILURE, "strdup()");
			drives[ndrives]->dt = get_disktype(path, drv.dc);
		} else {
			if (errno != 0) {
				logprint("Couldn't get physical device of %s",
				    dev);
			} else {
				logprintx("Couldn't get physical device of %s",
				    dev);
			}
			ndrives++;
			del_drive(drives[ndrives - 1]);

			return (NULL);
		}
	} else
		drives[ndrives]->dt = get_disktype(path, drv.dc);
	if (drives[ndrives]->dc->class == LLV)
		drives[ndrives]->polling = false;
	else if (drives[ndrives]->dc->class == CDROM ||
	    drives[ndrives]->dc->class == FLOPPY     ||
	    drives[ndrives]->dc->class == MMC	     ||
	    drives[ndrives]->dt->dt_type == DSK_TYPE_USBDISK)
		drives[ndrives]->polling = true;
	else
		drives[ndrives]->polling = false;

	if (drives[ndrives]->dc->system == CAM &&
	    drives[ndrives]->dc->class != LLV) {
		drives[ndrives]->model = get_cam_modelname(dev);
	} else if (drives[ndrives]->dc->system == ATA)
		drives[ndrives]->model = get_ata_modelname(dev);
	else
		drives[ndrives]->model = NULL;
	/* Ckeck if polling is undesirable for this device. */
	for (v = dsbcfg_getval(cfg, CFG_POLL_EXCEPTIONS).strings;
	    v != NULL && *v != NULL; v++) {
		if (drives[ndrives]->model == NULL)
			continue;
		if (fnmatch(*v, drives[ndrives]->model, FNM_CASEFOLD) == 0)
			drives[ndrives]->polling = false;
	}
	if (drives[ndrives]->polling)
		add_to_pollqueue(drives[ndrives]);
	if (drives[ndrives]->has_media && drives[ndrives]->fs != NULL)
		notifybc(drives[ndrives], true);
	return (drives[ndrives++]);
}

/*
 * Removes the given drive object from the drive list.
 */
static void
del_drive(drive_t *drvp)
{
	int i, j;

	for (i = 0; i < ndrives && drvp != drives[i]; i++)
		;
	if (i == ndrives)
		return;
	(void)pthread_mutex_lock(&drives[i]->mtx);
	(void)pthread_mutex_destroy(&drives[i]->mtx);

	del_from_pollqueue(drives[i]);

	if (drives[i]->has_media)
		notifybc(drives[i], false);
	/*
	 * Try to remove the mount table entry if the device was removed
	 * without unmounting it first.
	 */
	if (getmntpt(drives[i]) != NULL) {
		(void)unmount(drives[i]->mntpt, MNT_FORCE);
		(void)rmntpt(drives[i]->mntpt);
	}
	free(drives[i]->mntpt);
	free(drives[i]->dev);
	free(drives[i]->name);
	free(drives[i]->model);
	free(drives[i]->realdev);

	for (j = 0; j < NGLBLPRFX && drives[i]->glabel[j] != NULL; j++)
		free(drives[i]->glabel[j]);
	free(drives[i]);

	for (; i < ndrives - 1; i++)
		drives[i] = drives[i + 1];
	ndrives--;
}

/*
 * Looks up the given device in the disk class table.
 */
static const dskcl_t *
match_disk_pattern(const char *str)
{
	int	      i, j;
	size_t	      len;
	const char    *p;
	const dskcl_t *dc;

	str = devbasename(str);
	for (i = 0; i < NDISK_CLASSES; i++) {
		len = strlen(disk_classes[i].pattern);
		if (len && strncmp(str, disk_classes[i].pattern, len) == 0) {
			if (disk_classes[i].class == LLV) {
				if ((p = get_lv_dev(str)) != NULL)
					dc = match_disk_pattern(p);
				if (p == NULL || dc == NULL)
					return (&disk_classes[i]);
				for (j = 0; j < NDISK_CLASSES; j++)
					if (disk_classes[j].class == LLV &&
					    disk_classes[j].system ==
					    dc->system) {
						return (&disk_classes[j]);
					}
				return (&disk_classes[i]);
			}
			if (isalpha(str[len]) || str[len] == '\0') {
				/* No device number */
				continue;
			}
			return (&disk_classes[i]);
		}
	}
	return (NULL);
}

static char *
get_lv_dev(const char *path)
{
	static char	 dev[512], *p;
	struct gmesh	 mesh;
	struct ggeom	 *gp;
	struct gclass	 *cp;
	struct gprovider *pp;
	struct gconsumer *gc;

	if (geom_gettree(&mesh) != 0)
		return (NULL);
	cp = NULL;
	LIST_FOREACH(cp, &mesh.lg_class, lg_class) {
		if (strcmp(cp->lg_name, "LINUX_LVM") == 0)
			break;
	}
	if (cp == NULL) {
		geom_deletetree(&mesh);
		return (NULL);
	}
	LIST_FOREACH(gp, &cp->lg_geom, lg_geom) {
		if (LIST_EMPTY(&gp->lg_provider))
			continue;
		LIST_FOREACH(pp, &gp->lg_provider, lg_provider) {
			if (strcmp(pp->lg_name, path) == 0)
				break;
		}
		if (pp == NULL)
			return (NULL);
		gc = LIST_FIRST(&gp->lg_consumer);
		if (gc == NULL || gc->lg_provider == NULL) {
			geom_deletetree(&mesh);
			return (NULL);
		}
		pp = gc->lg_provider;
		if (strncmp(pp->lg_name, "gptid/", 6) == 0) {
			p = dev_from_gptid(pp->lg_name);
			if (p != NULL)
				(void)strncpy(dev, p, sizeof(dev) - 1);
			else {
				geom_deletetree(&mesh);
				return (NULL);
			}
		} else
			(void)strncpy(dev, pp->lg_name, sizeof(dev) - 1);
		geom_deletetree(&mesh);
		return (dev);
	}
	geom_deletetree(&mesh);
	return (NULL);
}

static char *
dev_from_gptid(const char *gptid)
{
	static char	 dev[128];
	struct gmesh	 mesh;
	struct ggeom	 *gp;
	struct gclass	 *cp;
	struct gprovider *pp;
	struct gconfig *conf;

	if (strncmp(gptid, "gptid/", 6) == 0)
		gptid += 6;
	if (geom_gettree(&mesh) != 0)
		return (NULL);
	LIST_FOREACH(cp, &mesh.lg_class, lg_class) {
		if (strcmp(cp->lg_name, "PART") != 0)
			continue;
		LIST_FOREACH(gp, &cp->lg_geom, lg_geom) {
			if (LIST_EMPTY(&gp->lg_provider))
				continue;
			LIST_FOREACH(pp, &gp->lg_provider, lg_provider) {
				LIST_FOREACH(conf, &pp->lg_config, lg_config) {
					if (strcmp(conf->lg_name,
					    "rawuuid") == 0 &&
					    strcmp(gptid, conf->lg_val) == 0) {
						strncpy(dev, pp->lg_name,
						    sizeof(dev));
						geom_deletetree(&mesh);
						return (dev);
					}
        			}
			}
		}
	}
	geom_deletetree(&mesh);

	return (NULL);
}

/*
 * Reads the modelname from a CAM device. This information can be used for
 * device specific configurations.  See  the "poll_exceptions"-variable in
 * dsbmd.conf.
 */
static char *
get_cam_modelname(const char *dev)
{
	int  len;
	char *p, *path, *model, *disk;
	struct cam_device *cd;

	dev = devbasename(dev);
	if ((path = malloc(MNAMELEN)) == NULL) {
		logprint("malloc()");
		return (NULL);
	}
	(void)snprintf(path, MNAMELEN, "%s%s", _PATH_DEV, dev);
	disk = get_diskname(path);
	if ((cd = cam_open_device(disk, O_RDWR)) == NULL)
                logprint("cam_open_device(%s): %s", disk, cam_errbuf);
	free(path);
	if (cd == NULL)
		return (NULL);
	/* Nul-terminate vendor name, and remove trailing whitespaces. */
	p = cd->inq_data.vendor + sizeof(cd->inq_data.vendor) - 1;
	while (p != cd->inq_data.vendor && (isspace(*p) || *p == '\0'))
		*p-- = '\0';
	/* Nul-terminate product name, and remove trailing whitespaces. */
	p = cd->inq_data.product + sizeof(cd->inq_data.product) - 1;
	while (p != cd->inq_data.product && (isspace(*p) || *p == '\0'))
		*p-- = '\0';
	/* Nul-terminate revision string, and remove trailing whitespaces. */
	p = cd->inq_data.revision + sizeof(cd->inq_data.revision) - 1;
	while (p != cd->inq_data.revision && (isspace(*p) || *p == '\0'))
		*p-- = '\0';
	len = strlen(cd->inq_data.vendor)   + strlen(cd->inq_data.product) +
	      strlen(cd->inq_data.revision) + 2;
	if ((model = malloc(len)) == NULL) {
		cam_close_device(cd);
		return (NULL);
	}
	(void)snprintf(model, len, "%s %s %s", cd->inq_data.vendor,
	    cd->inq_data.product, cd->inq_data.revision);
	cam_close_device(cd);

	return (model);
}

/*
 * Reads the modelname from a ATA device. This information can be used for
 * device specific configurations.  See  the "poll_exceptions"-variable in
 * dsbmd.conf.
 */
static char *
get_ata_modelname(const char *dev)
{
	int   chan, i, fd, len, maxchan;
	char *p;
	struct ata_ioc_devices atadev;
	
	dev = devbasename(dev);
	if ((fd = open("/dev/ata", O_RDONLY)) == -1)
		err(EXIT_FAILURE, "open(/dev/ata)");
	if (ioctl(fd, IOCATAGMAXCHANNEL, &maxchan) == -1)
		err(EXIT_FAILURE, "ioctl(IOCATAGMAXCHANNEL)");
	for (chan = 0; chan < maxchan; chan++) {
		atadev.channel = chan;
		if (ioctl(fd, IOCATADEVICES, &atadev) == -1)
			continue;
		for (i = 0; i < 2; i++) {
			/* Just compare the diskname, not the slice. */
			len = strlen(atadev.name[i]);
			if (len > 0 && strncmp(atadev.name[i], dev, len) == 0)
				break;
		}
		if (i < 2)
			break;
	}
	(void)close(fd);

	if (chan >= maxchan || i >= 2)
		return (NULL);
	/* Nul-terminate model name, and remove trailing whitespaces. */
	p = (char *)atadev.params[i].model +
	    sizeof(atadev.params[i].model) - 1;
	while (p != (char *)atadev.params[i].model &&
	    (isspace(*p) ||  *p == '\0'))
		*p-- = '\0';
	/* Nul-terminate revision string, and remove trailing whitespaces. */
	p = (char *)atadev.params[i].revision +
	    sizeof(atadev.params[i].revision) - 1;
	while (p != (char *)atadev.params[i].revision &&
	    (isspace(*p) ||  *p == '\0'))
		*p-- = '\0';
	len = strlen((char *)atadev.params[i].model) +
	      strlen((char *)atadev.params[i].revision);
	if ((p = malloc(len)) == NULL)
		return (NULL);
	(void)sprintf(p, "%s %s", atadev.params[i].model,
	    atadev.params[i].revision);
	return (p);
}

/*
 * Unmounts a CD/DVD and ejects it. If 'force' is true, unmounting
 * the media, even if it's busy, will be enforced.
 */
static int
eject_media(client_t *cli, drive_t *drvp, bool force)
{
	int	  fd, i, error;
	char	  *disk;
	union ccb *ccb;
	struct cam_device *cd;

	if ((drvp->mounted && drvp->fs->mntcmd != NULL) ||
	    getmntpt(drvp) != NULL) {
		if ((error = unmount_drive(cli, drvp, force, true)) != 0) {
			cliprint(cli, "E:command=eject:code=%d", error);
			return (error);
		}
	}
	if (drvp->dc->system == ATA) {
		if (drvp->dc->class != CDROM) {
			cliprint(cli, "E:command=eject:code=%d",
			    ERR_NOT_EJECTABLE);
			return (ERR_NOT_EJECTABLE);
		}
		if ((fd = open(drvp->dev, O_RDWR)) == -1) {
			cliprint(cli, "E:command=eject:code=%d", errno);
			logprint("Opening of %s by UID %d failed", drvp->dev,
			    cli->uid);
			return (errno);
		}
		if (ioctl(fd, CDIOCALLOW) == -1 || ioctl(fd, CDIOCEJECT) == -1)
			error = errno;
		else
			error = 0;
		(void)close(fd);
	} else if (drvp->dc->system == CAM) {
		if (drvp->dc->class == LLV)
			disk = get_diskname(drvp->realdev);
		else
			disk = get_diskname(drvp->dev);
		if ((cd = cam_open_device(disk, O_RDWR)) == NULL) {
			cliprint(cli, "E:command=eject:code=%d", errno);
			logprint("cam_open_device(%s)", disk);
			return (errno);
		}
		if ((ccb = cam_getccb(cd)) == NULL) {
			error = errno;
			cliprint(cli, "E:command=eject:code=%d", error);
			logprint("cam_getccb()");
			cam_close_device(cd);
			return (error);
		}
		scsi_start_stop(&ccb->csio, 1, NULL, MSG_ORDERED_Q_TAG,
		    0, 1, 0, 0, 100000);
		for (i = 0; i < 3; i++) {
			if (cam_send_ccb(cd, ccb) == -1) {
				error = errno;
				logprint("cam_send_ccb()");
			} else if ((ccb->ccb_h.status & CAM_STATUS_MASK) ==
			    CAM_REQ_CMP) {
				error = 0;
				/*
				 * Some USB devices must be accessed to make
				 * them remove the associated CAM device.
				 */
				(void)has_media(drvp->dev);
				break;
			} else
				error = -1;
		}
		cam_close_device(cd);
		cam_freeccb(ccb);
	} else {
		cliprint(cli, "E:command=eject:code=%d", ERR_NOT_EJECTABLE);
		return (ERR_NOT_EJECTABLE);
	}
	if (error != 0) {
		cliprint(cli, "E:command=eject:code=%d", error);
		if (error > (1 << 8))
			logprint("Ejecting %s by UID %d failed", drvp->dev,
			    cli->uid);
		else
			logprintx("Ejecting %s by UID %d failed", drvp->dev,
			    cli->uid);
	} else
		cliprint(cli, "O:command=eject");
	return (error);
}

static int
set_cdrspeed(client_t *cli, drive_t *drvp, int speed)
{
	int fd, error;

	if (speed > CDR_MAX_SPEED || speed <= 0) {
		cliprint(cli, "E:command=speed:code=%d", ERR_INVALID_ARGUMENT);
		return (ERR_INVALID_ARGUMENT);
	}
	speed *= 177;
	
	if ((fd = open(drvp->dev, O_RDWR)) == -1) {
		cliprint(cli, "E:command=speed:code=%d", errno);
		logprint("open(%s)", drvp->dev);
		return (errno);
	}
	if (ioctl(fd, CDRIOCREADSPEED, &speed) == -1) {
		error = errno;
		logprint("ioctl(%s, CDRIOCREADSPEED, %d)", drvp->dev,
		    speed / 177);
		cliprint(cli, "E:command=speed:code=%d", errno);
	} else {
		error = 0;
		drvp->speed = speed / 177;
		cliprint(cli, "O:command=speed:speed=%d", drvp->speed);
		cliprintbc(cli, "I:msgtype=speed:speed=%d:dev=%s",
		    drvp->speed, drvp->dev);
	}
	(void)close(fd);

	return (error);
}

/*
 * Check if the given device is an ATAPICAM device.
 */
static bool
is_atapicam(const char *dev)
{
	int  fd, chan, maxchan;
	char *disk;
	bool atapicam;
	struct cam_device *cd;
	struct ata_ioc_devices atadev;

	/* 
	 * If  ATA_CAM  is enabled, it deprecates all ATA drivers, and all ATA
	 * device  interface  names  will be replaced by the corresponding CAM
	 * names. Hence, checking if e.g. cd0's controller name is "ata", will
	 * result  in  a false positive. So we have to check if an ATAPI CDROM
	 * drive is installed.
	 */
	if ((fd = open("/dev/ata", O_RDONLY)) == -1) {
		if (errno == ENOENT || errno == EINVAL)
			return (false);
		err(EXIT_FAILURE, "open(/dev/ata)");
	}
	if (ioctl(fd, IOCATAGMAXCHANNEL, &maxchan) == -1) {
		(void)close(fd);
		return (false);
	}
	for (chan = 0; chan < maxchan; chan++) {
		atadev.channel = chan;
		if (ioctl(fd, IOCATADEVICES, &atadev) == -1)
			continue;
		if ((atadev.params[0].config & ATA_ATAPI_TYPE_CDROM) ||
		    (atadev.params[1].config & ATA_ATAPI_TYPE_CDROM))
			break;
	}
	(void)close(fd);

	if (chan >= maxchan)
		/* No ATAPI CDROM found, hence no atapi cam.*/
		return (false);
	/* Check if the CDROM drive's controller is "ata". */
	atapicam = false;
	disk = get_diskname(dev);
	if ((cd = cam_open_device(disk, O_RDWR)) != NULL) {
		if (strcmp(cd->sim_name, "ata") == 0)
			atapicam = true;
		cam_close_device(cd);
	} else
		logprint("cam_open_device(): %s", cam_errbuf);
	return (atapicam);
}

/* 
 * Connect to a UNIX domain socket, and return a standard I/O file pointer
 * to it. 
 */
static FILE *
uconnect(const char *path)
{
	int		   s;
	FILE		  *sp;
	struct sockaddr_un saddr;

	if ((s = socket(PF_LOCAL, SOCK_STREAM, 0)) == -1)
		return (NULL);
	(void)memset(&saddr, (unsigned char)0, sizeof(saddr));
	(void)snprintf(saddr.sun_path, sizeof(saddr.sun_path), "%s", path);
	saddr.sun_family = AF_LOCAL;
	if (connect(s, (struct sockaddr *)&saddr, sizeof(saddr)) == -1)
		return (NULL);
	if ((sp = fdopen(s, "r+")) == NULL)
		return (NULL);
	/* Make the stream line buffered, and the socket non-blocking. */
	if (setvbuf(sp, NULL, _IOLBF, 0) == -1 ||
	    fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK) == -1)
		return (NULL);
	return (sp);
}

static void
cliprint(client_t *cli, const char *fmt, ...)
{
	int	saved_errno;
	va_list	ap;

	saved_errno = errno;
	(void)pthread_mutex_lock(&cli->mtx);
	va_start(ap, fmt);
	(void)vfprintf(cli->s, fmt, ap);
	(void)fputc('\n', cli->s);
	(void)pthread_mutex_unlock(&cli->mtx);
	errno = saved_errno;
}

static void
cliprintbc(client_t *exclude, const char *fmt, ...)
{
	int	i, saved_errno;
	va_list	ap;

	saved_errno = errno;
	va_start(ap, fmt);
	for (i = 0; i < nclients; i++) {
		if (exclude == clients[i])
			continue;
		(void)pthread_mutex_lock(&clients[i]->mtx);
		(void)vfprintf(clients[i]->s, fmt, ap);
		(void)fputc('\n', clients[i]->s);
		(void)pthread_mutex_unlock(&clients[i]->mtx);
	}
	errno = saved_errno;
}

/*
 * Send a device add/remove string to a client.
 */
static void
notify(client_t *cli, drive_t *drvp, bool add)
{
	int  len;
	char buf[_POSIX2_LINE_MAX];

	if (add) {
		len = 0;
		len += snprintf(buf + len, sizeof(buf) - len, "+:dev=%s",
		    drvp->dev);
		if (drvp->fs != NULL) {
			len += snprintf(buf + len, sizeof(buf) - len, ":fs=%s",
			    drvp->fs->name);
		}
		if (drvp->name != NULL) {
			len += snprintf(buf + len, sizeof(buf) - len,
			    ":volid=%s", drvp->name);
		}
		if (drvp->mntpt != NULL) {
			len += snprintf(buf + len, sizeof(buf) - len,
			    ":mntpt=%s", drvp->mntpt);
		}
		len += snprintf(buf + len, sizeof(buf) - len, ":type=%s",
		    drvp->dt->dt_name);
		if (drvp->dc->class == CDROM) {
			len += snprintf(buf + len, sizeof(buf) - len,
			    ":speed=%d", drvp->speed);
			if (drvp->fs != NULL) {
				len += snprintf(buf + len, sizeof(buf) - len,
				    ":cmds=mount,unmount,eject,speed");
			} else {
				len += snprintf(buf + len, sizeof(buf) - len,
				    ":cmds=eject,speed");
			}
		} else if (drvp->dc->system == CAM) {
			if (drvp->fs != NULL) {
				len += snprintf(buf + len, sizeof(buf) - len,
				    ":cmds=mount,unmount,eject");
			}
		} else if (drvp->fs != NULL) {
			len += snprintf(buf + len, sizeof(buf) - len,
			    ":cmds=mount,unmount");
		}
		cliprint(cli, "%s", buf);
	} else {
		/* -<dev> */
		cliprint(cli, "-:dev=%s", drvp->dev);
	}
}

/*
 * Send a device add/remove string to all clients.
 */
static void
notifybc(drive_t *drvp, bool add)
{
	int i;

	for (i = 0; i < nclients; i++)
		notify(clients[i], drvp, add);
}

static int
waitforbytes(FILE *s)
{
	int    n;
	fd_set rset;

	FD_ZERO(&rset);
	FD_SET(fileno(s), &rset);
	while ((n = select(fileno(s) + 1, &rset, 0, 0, 0)) < 0) {
		if (errno == EINTR)
			continue;
		else
			err(EXIT_FAILURE, "select()");
	}
	return (n);
}

/*
 * Client thread function - Reads lines from the client's socket, parses
 * them and takes actions accordingly.
 */
static void *
serve_client(void *cp)
{
	int	 c, n, rd;
	char	 buf[64];
	bool	 badchar;
	client_t *cli;

	cli = (client_t *)cp;
	for (;;) {
		(void)waitforbytes(cli->s);
		/*
		 * Read a line from socket. If the line is longer than
		 * sizeof(buf), or if it contains unprintable bytes, read
		 * until end of line, and send the client an error message.
		 */
		for (badchar = false, c = n = rd = 0; c != '\n'; rd++) {
			if ((c = fgetc(cli->s)) == EOF) {
				if (feof(cli->s)) {
					/* Client disconnected. */
					(void)pthread_mutex_lock(&cli_mtx);
					del_client(cli);
					(void)pthread_mutex_unlock(&cli_mtx);
	
					return (NULL);
				} else if (errno == EAGAIN || errno == EINTR)
					(void)waitforbytes(cli->s);
				else
					err(EXIT_FAILURE, "fgetc()");
			}
			if (n < sizeof(buf) - 1)
				buf[n++] = c;
			buf[n] = '\0';
			if (c != '\n' && !isprint(c))
				badchar = true;
		}
		if (badchar)
			cliprint(cli, "E:code=%d\n", ERR_BAD_STRING);
		else if (n != rd)
			cliprint(cli, "E:code=%d\n", ERR_STRING_TOO_LONG);
		else
			exec_cmd(cli, buf);
	}
	/* NOTREACHED */
	return (NULL);
}

static void
exec_cmd(client_t *cli, char *cmdstr)
{
	int  argc, i;
	char *p, *last, *argv[12];
	struct command_s *cp;

	for (p = strtok_r(cmdstr, "\t\n\r ", &last), argc = 0;
	    argc < sizeof(argv) / sizeof(char *) && p != NULL; argc++) {
		argv[argc] = p;
		p = strtok_r(NULL, "\t\n\r ", &last);
	}
	argv[argc] = NULL;
	for (cp = NULL, i = 0; cp == NULL && i < NCOMMANDS; i++) {
		if (argv[0] != NULL && strcmp(argv[0], commands[i].cmd) == 0)
			cp = &commands[i];
	}
	if (cp == NULL) {
		cliprint(cli, "E:command=%s:code=%d", argv[0],
		    ERR_UNKNOWN_COMMAND);
	} else
		cp->cmdf(cli, argv + 1);
}

static void
cmd_eject(client_t *cli, char **argv)
{
	int	i;
	bool	force;
	drive_t *drvp;

	force = false;
	for (i = 0; argv[i] != NULL && argv[i][0] == '-'; i++) {
		if (strcmp(&argv[i][1], "f") == 0)
			force = true;
		else {
			cliprint(cli, "E:command=eject:code=%d",
			    ERR_UNKNOWN_OPTION);
			return;
		}
	}
	if (argv[i] == NULL) {
		cliprint(cli, "E:command=eject:code=%d", ERR_SYNTAX_ERROR);
		return;
	}
	(void)pthread_mutex_lock(&drv_mtx);
	if ((drvp = lookupdrv(argv[i])) == NULL) {
		cliprint(cli, "E:command=eject:code=%d", ERR_NO_SUCH_DEVICE);
		(void)pthread_mutex_unlock(&drv_mtx);
		return;
	}
	(void)pthread_mutex_lock(&drvp->mtx);
	(void)pthread_mutex_unlock(&drv_mtx);
	(void)eject_media(cli, drvp, force);
	(void)pthread_mutex_unlock(&drvp->mtx);
}

static void
cmd_size(client_t *cli, char **argv)
{
	int	      n, fd;
	drive_t	      *drvp;
	struct statfs s;

	if (argv[0] == NULL) {
		cliprint(cli, "E:command=size:code=%d", ERR_SYNTAX_ERROR);
		return;
	}
	(void)pthread_mutex_lock(&drv_mtx);
	if ((drvp = lookupdrv(argv[0])) == NULL) {
		cliprint(cli, "E:command=size:code=%d", ERR_NO_SUCH_DEVICE);
		(void)pthread_mutex_unlock(&drv_mtx);
		return;
	}
	(void)pthread_mutex_lock(&drvp->mtx);
	(void)pthread_mutex_unlock(&drv_mtx);
	if (drvp->mntpt != NULL) {
		/*
		 * If a device was just mounted, it can happen that the
		 * size information queried by statfs() are not correct.
		 * We retry and give the system some time if the returned
		 * number of blocks is <= 0.
		 */
		n = 0;
		do {
			if (n)
				usleep(500000);
			if (statfs(drvp->mntpt, &s) == -1) {
				cliprint(cli, "E:command=size:code=%d", errno);
				(void)pthread_mutex_unlock(&drvp->mtx);
				return;
			}
		} while (n++ < 3 && s.f_blocks <= 1);

		cliprint(cli,
		    "O:command=size:dev=%s:mediasize=%llu:free=%llu:used=%llu",
		    drvp->dev,
		    (uint64_t)(s.f_blocks * s.f_bsize),
		    (uint64_t)(s.f_bsize  * s.f_bfree),
		    (uint64_t)(s.f_bsize  * (s.f_blocks - s.f_bfree)));
	} else {
		if ((fd = open(drvp->dev, O_RDONLY | O_NONBLOCK)) == -1) {
			cliprint(cli, "E:command=size:code=%d", errno);
			(void)pthread_mutex_unlock(&drvp->mtx);
			return;
		}
		cliprint(cli,
		    "O:command=size:dev=%s:mediasize=%llu:free=0:used=0",
		    drvp->dev, (uint64_t)g_mediasize(fd));
		(void)close(fd);
	}
	(void)pthread_mutex_unlock(&drvp->mtx);
}

static void
cmd_speed(client_t *cli, char **argv)
{
	int	speed;
	drive_t *drvp;

	if (argv[0] == NULL || argv[1] == NULL) {
		cliprint(cli, "E:command=speed:code=%d", ERR_SYNTAX_ERROR);
		return;
	}
	(void)pthread_mutex_lock(&drv_mtx);
	if ((drvp = lookupdrv(argv[0])) == NULL) {
		cliprint(cli, "E:command=speed:code=%d", ERR_NO_SUCH_DEVICE);
		(void)pthread_mutex_unlock(&drv_mtx);
		return;
	}
	speed = strtol(argv[1], NULL, 10);
	(void)pthread_mutex_lock(&drvp->mtx);
	(void)pthread_mutex_unlock(&drv_mtx);
	(void)set_cdrspeed(cli, drvp, speed);
	(void)pthread_mutex_unlock(&drvp->mtx);
}

static void
cmd_mount(client_t *cli, char **argv)
{
	drive_t *drvp;

	if (argv[0] == NULL) {
		cliprint(cli, "E:command=mount:code=%d", ERR_SYNTAX_ERROR);
		return;
	}
	(void)pthread_mutex_lock(&drv_mtx);
	if ((drvp = lookupdrv(argv[0])) == NULL) {
		cliprint(cli, "E:command=mount:code=%d", ERR_NO_SUCH_DEVICE);
		(void)pthread_mutex_unlock(&drv_mtx);
		return;
	}
	(void)pthread_mutex_lock(&drvp->mtx);
	(void)pthread_mutex_unlock(&drv_mtx);
	(void)mount_drive(cli, drvp);
	(void)pthread_mutex_unlock(&drvp->mtx);
}

static void
cmd_unmount(client_t *cli, char **argv)
{
	int	i;
	bool	force;
	drive_t *drvp;

	force = false;
	for (i = 0; argv[i] != NULL && argv[i][0] == '-'; i++) {
		if (strcmp(&argv[i][1], "f") == 0)
			force = true;
		else {
			cliprint(cli, "E:command=unmount:code=%d",
			    ERR_UNKNOWN_OPTION);
			return;
		}
	}
	if (argv[i] == NULL) {
		cliprint(cli, "E:command=unmount:code=%d", ERR_SYNTAX_ERROR);
		return;
	}
	(void)pthread_mutex_lock(&drv_mtx);
	if ((drvp = lookupdrv(argv[i])) == NULL) {
		cliprint(cli, "E:command=unmount:code=%d", ERR_NO_SUCH_DEVICE);
		(void)pthread_mutex_unlock(&drv_mtx);
		return;
	}
	(void)pthread_mutex_lock(&drvp->mtx);
	(void)pthread_mutex_unlock(&drv_mtx);
	(void)unmount_drive(cli, drvp, force, false);
	(void)pthread_mutex_unlock(&drvp->mtx);
}

static void
cmd_quit(client_t *cli, char **argv)
{
	(void)pthread_mutex_lock(&cli_mtx);
	del_client(cli);
	(void)pthread_mutex_unlock(&cli_mtx);
	pthread_exit(NULL);
}

static void *
thr_check_mntbl(void *unused)
{
	int n;
	struct statfs buf[MAXDEVS];

	for (;; usleep(MNTCHK_INTERVAL)) {
		if ((n = getfsstat(buf, sizeof(buf), MNT_WAIT)) == -1) {
			logprint("getfsstat()");
			continue;
		}
		(void)pthread_mutex_lock(&drv_mtx);
		check_mntbl(buf, n);
		check_fuse_mount(buf, n);
		check_fuse_unmount(buf, n);
		(void)pthread_mutex_unlock(&drv_mtx);
	}
}

static void
check_fuse_mount(struct statfs *sb, int nsb)
{
	int	   i, j;
	bool	   found;
	drive_t	   *dp;
	const char *q;

	for (i = 0; i < nsb; i++) {
		q = devbasename(sb[i].f_mntfromname);
		/* Check for new FUSE device mounts */
		if (strncmp(q, "fuse", 4) == 0) {
			for (found = false, j = 0; j < ndrives && !found; j++) {
				dp = drives[j];
				if (dp->mntpt == NULL)
					continue;
				if (strcmp(dp->mntpt, sb[i].f_mntonname) == 0)
					found = true;
			}
			if (!found) {
				/* New FUSE device mounted. */
				(void)pthread_mutex_lock(&drv_mtx);
				add_fuse_device(sb[i].f_mntonname);
				(void)pthread_mutex_unlock(&drv_mtx);
				return;
			}
		}
	}
}

static void
check_fuse_unmount(struct statfs *sb, int nsb)
{
	int  i, j;
	bool found;

	for (i = 0; i < ndrives; i++) {
		if (drives[i]->dc->class != FUSE)
			continue;
		if (pthread_mutex_trylock(&drives[i]->mtx) != 0)
			continue;
		for (j = 0, found = false; !found && j < nsb; j++) {
			if (strcmp(drives[i]->mntpt, sb[j].f_mntonname) == 0)
				found = true;
		}
		if (!found) {
			pthread_mutex_unlock(&drives[i]->mtx);
			del_drive(drives[i]);
			(void)pthread_mutex_unlock(&drv_mtx);
			return;
		}
		pthread_mutex_unlock(&drives[i]->mtx);
	}
}


static void
check_mntbl(struct statfs *sb, int nsb)
{
	int	   i, j, k;
	bool	   found;
	drive_t	   *dp;
	const char *p, *q, *mntpt;

	for (i = 0; i < ndrives; i++) {
		if (drives[i]->dc->class == FUSE)
			continue;
		if (pthread_mutex_trylock(&drives[i]->mtx) != 0)
			continue;
		dp = drives[i];
		for (j = 0, found = false; !found && j < nsb; j++) {
			q = devbasename(sb[j].f_mntfromname);
			if (strcmp(devbasename(dp->dev), q) != 0) {
				/*
				 * Check if the drive was mounted using its
				 * glabel.
				 */
				for (k = 0; !found && k < NGLBLPRFX &&
				    dp->glabel[k] != NULL; k++) {
					/*
					 * Skip the glabel-prefix (ufs/,
					 * cd9660/, etc.).
					 */
					if ((p = strchr(dp->glabel[k],
					    '/')) != NULL)
						p++;
					else
						p = dp->glabel[k];
					if (strcmp(dp->glabel[k], q) == 0 ||
					    strcmp(p, q) == 0)
						found = true;
				}
			} else
				found = true;
			if (found)
				mntpt = sb[j].f_mntonname;
		}
		if (found) {
			if (!dp->mounted || dp->mntpt == NULL) {
				/* Mounted. */
				dp->mntpt = strdup(mntpt);
				if (dp->mntpt == NULL)
					err(EXIT_FAILURE, "strdup()");
				dp->mounted = true;
				cliprintbc(NULL,
				    "I:msgtype=mount:dev=%s:mntpt=%s",
				    dp->dev, dp->mntpt);
			} else if (dp->mounted &&
			    strcmp(dp->mntpt, mntpt) != 0) {
				/* Remounted */
				cliprintbc(NULL,
				    "I:msgtype=unmount:dev=%s:mntpt=%s",
				    dp->dev, dp->mntpt);
				free(dp->mntpt);
				dp->mntpt = strdup(mntpt);
				if (dp->mntpt == NULL)
					err(EXIT_FAILURE, "strdup()");
				cliprintbc(NULL,
 				    "I:msgtype=mount:dev=%s:mntpt=%s",
				    dp->dev, dp->mntpt);
			}
		} else if (dp->mounted) {
			if (dp->fs->mntcmd != NULL) {
				if (is_mntpt(dp->mntpt)) {
					(void)pthread_mutex_unlock(&dp->mtx);
					continue;
				}
			}	
			/* Unmounted */
			cliprintbc(NULL, "I:msgtype=unmount:dev=%s:mntpt=%s",
			    dp->dev, dp->mntpt);
			free(dp->mntpt);
			dp->mntpt   = NULL;
			dp->mounted = false;
		}
		(void)pthread_mutex_unlock(&dp->mtx);
	}
}

