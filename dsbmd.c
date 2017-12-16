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
#include <signal.h>
#include <ctype.h>
#include <limits.h>
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
#include <sys/wait.h>
#include <login_cap.h>
#include <time.h>
#include <unistd.h>
#include <vm/vm_param.h>
#include <dirent.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <regex.h>
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
#include <libusb20_desc.h>
#include <libusb20.h>
#include "common.h"
#include "fs.h"
#include "dsbmd.h"
#include "dsbcfg/dsbcfg.h"
#include "config.h"
#include <sys/iconv.h>

#define MNTPTMODE	   (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
#define MNTDIRPERM	   (S_IRWXU | S_IXGRP | S_IRGRP | S_IXOTH | S_IROTH)
#define NCOMMANDS	   (sizeof(commands) / sizeof(struct command_s))

#define USB_CLASS_UMASS	   0x08
#define USB_SUBCLASS_UMASS 0x06
#define USB_SUBCLASS_MMC   0x02
#define USB_CLASS_PTP	   0x06
#define USB_SUBCLASS_PTP   0x01
#define USB_PROTOCOL_PTP   0x01

#define INITFS(i, ID) do {						     \
	fstype[i].mntcmd   = dsbcfg_getval(cfg, CFG_##ID##_MNTCMD).string;   \
	fstype[i].mntcmd_u = dsbcfg_getval(cfg, CFG_##ID##_MNTCMD_U).string; \
	fstype[i].uopts	   = dsbcfg_getval(cfg, CFG_##ID##_OPTS).string;     \
} while (0)

static int	change_owner(sdev_t *, uid_t);
static int	ssystem(uid_t, const char *);
static int	devstat(const char *, struct stat *);
static int	get_ugen_type(const char *);
static int	get_optical_disk_type(const char *);
static int	get_da_storage_type(const char *);
static int	mymount(const char *, const char *, const char *,
		    const char *, uid_t, gid_t);
static int	mount_device(client_t *, sdev_t *);
static int	unmount_device(client_t *, sdev_t *, bool, bool);
static int	exec_mntcmd(client_t *, sdev_t *, char *);
static int	extend_iovec(struct iovec **, int *, const char *,
		    const char *);
static int	eject_media(client_t *, sdev_t *, bool);
static int	set_cdrspeed(client_t *, sdev_t *, int);
static int	set_msdosfs_locale(const char *, struct iovec**, int *);
static int	uconnect(const char *);
static int	devd_connect(void);
static int	send_string(int, const char *);
static int	client_readln(client_t *, int *);
static int	serve_client(client_t *);
static bool	match_part_dev(const char *, size_t);
static bool	match_glabel(sdev_t *, const char *);
static bool	has_media(const char *);
static bool	is_parted(const char *);
static bool	is_mountable(const char *);
static bool	is_mntpt(const char *);
static bool	check_permission(uid_t, gid_t *);
static bool	usermount_set(void);
static char	*read_devd_event(int, int *);
static char	**extend_list(char **, int *, const char *);
static char	*mkmntpt(const sdev_t *);
static char	*getmntpt(sdev_t *);
static char	*get_cam_modelname(const char *);
static char	*get_diskname(const char *);
static char	*get_lvm_dev(const char *);
static char	*dev_from_gptid(const char *);
static char	*ugen_to_gphoto_port(const char *);
static void	lockpidfile(void);
static void	process_devd_event(char *);
static void	usage(void);
static void	setuserenv(uid_t);
static void	switcheids(uid_t, gid_t);
static void	restoreids(void);
static void	rmntpt(const char *);
static void	cleanup(int);
static void	del_device(sdev_t *);
static void	del_client(client_t *);
static void	update_device(sdev_t *);
static void	parse_devd_event(char *);
static void	free_iovec(struct iovec *);
static void	add_to_pollqueue(sdev_t *);
static void	del_from_pollqueue(sdev_t *);
static void	exec_cmd(client_t *, char *);
static void	cmd_eject(client_t *, char **);
static void	cmd_speed(client_t *, char **);
static void	cmd_size(client_t *, char **);
static void	cmd_mount(client_t *, char **);
static void	cmd_unmount(client_t *, char **);
static void	cmd_quit(client_t *cli, char **);
static void	notifybc(sdev_t *, bool);
static void	notify(client_t *, sdev_t *, bool);
static void	cliprint(client_t *, const char *, ...);
static void	cliprintbc(client_t *, const char *, ...);
static void	check_mntbl(struct statfs *, int);
static void	check_fuse_mount(struct statfs *, int);
static void	check_fuse_unmount(struct statfs *, int);
static time_t	poll_mntbl(void);
static time_t	do_poll(void);
static sdev_t	*add_device(const char *);
static sdev_t	*add_ptp_device(const char *);
static sdev_t	*add_mtp_device(const char *);
static sdev_t	*media_changed(void);
static sdev_t	*lookup_dev(const char *);
static client_t	*add_client(int);
static client_t	*process_connreq(int);
static const storage_type_t *get_storage_type(const char *);

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

const storage_type_t storage_types[] = {
	{ "HDD",	ST_HDD       },
	{ "MMC",	ST_MMC       }, 
	{ "VCD",	ST_VCD       },
	{ "SVCD",	ST_SVCD      },
	{ "DVD",	ST_DVD       },
	{ "AUDIOCD",	ST_CDDA	     },
	{ "DATACD",	ST_DATACD    },
	{ "USBDISK",	ST_USBDISK   },
	{ "MTP",	ST_MTP	     },
	{ "PTP",	ST_PTP	     },
	{ "HDD",	ST_FUSE	     }
};

const iface_t interfaces[] = {
	{ RE_CD,	IF_TYPE_CD   },
	{ RE_ADA,	IF_TYPE_ADA  },
	{ RE_DA,	IF_TYPE_DA   },
	{ RE_UGEN,	IF_TYPE_UGEN },
	{ RE_LVM,	IF_TYPE_LVM  },
	{ RE_MMC,	IF_TYPE_MMC  },
	{ RE_MD,	IF_TYPE_MD   },
	{ RE_FUSE,	IF_TYPE_FUSE }
};

/*
 * Struct to assign command strings/names to a function.
 */
struct command_s {
	const char *cmd;
	void (*cmdf)(client_t *, char **);
} commands[] = {
	{ "quit",	&cmd_quit    },
	{ "mount",	&cmd_mount   },
	{ "unmount",	&cmd_unmount },
	{ "eject",	&cmd_eject   },
	{ "speed",	&cmd_speed   },
	{ "size",	&cmd_size    }
};

static int	nclients    = 0;	/* # of connected clients. */
static int	ndevs	    = 0;	/* # of devs. */
static int	queuesz	    = 0;	/* # of devices in poll queue. */
static FILE	*lockfp	    = NULL;	/* Filepointer for lock file. */
static uid_t    *allow_uids = NULL;	/* UIDs allowed to connect. */
static gid_t    *allow_gids = NULL;	/* GIDs allowed to connect. */
static sdev_t	**pollqueue = NULL;	/* List of devices to poll. */
static sdev_t	**devs      = NULL;	/* List of mountable devs. */
static client_t **clients   = NULL;	/* List of connected clients. */
static dsbcfg_t *cfg	    = NULL;

int
main(int argc, char *argv[])
{
	int	       i, e, sflags, maxfd, ch, dsock, lsock, minsecs;
	int	       mntchkiv, polliv;
	DIR	       *dirp, *dirp2;
	bool	       fflag, polling;
	FILE	       *fp;
	char	       lvmpath[512], *ev, **v;
	time_t	       polltime, mntchktime;
	fd_set	       allset, rset;
	client_t       *cli;
	struct stat    sb;
	struct group   *gr;
	struct passwd  *pw;
	struct dirent  *dp, *dp2;
	struct timeval tv;
	struct sockaddr_un s_addr;

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

	/*
	 * Preload the given filesystem kmods.
	 */
	for (v = dsbcfg_getval(cfg, CFG_PRELOAD_KMODS).strings;
	    v != NULL && *v != NULL; v++) {
		if (modfind(*v) == -1 && errno == ENOENT) {
			if (kldload(*v) == -1 && errno != EEXIST)
				logprint("kldload(%s)", *v);
		}
	}
	mntchkiv = dsbcfg_getval(cfg, CFG_MNTCHK_INTERVAL).integer; 
	polliv = dsbcfg_getval(cfg, CFG_POLL_INTERVAL).integer;

	for (i = 0; i < nfstypes; i++) {
		switch (fstype[i].id) {
		case UFS:
			INITFS(i, UFS);
			break;
		case CD9660:
			INITFS(i, CD9660);
			break;
		case MSDOSFS:
			INITFS(i, MSDOSFS);
			break;
		case NTFS:
			INITFS(i, NTFS);
			break;
		case EXT4:
			INITFS(i, EXT4);
			break;
		case EXT:
			INITFS(i, EXT);
			break;
		case EXFAT:
			INITFS(i, EXFAT);
			break;
		case MTPFS:
			INITFS(i, MTPFS);
			break;
		case PTPFS:
			INITFS(i, PTPFS);
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
		lockpidfile();
		/* Close all files except for the lock file. */
		for (i = 0; i < 16; i++) {
			if (fileno(lockfp) != i)
				(void)close(i);
		}
		/* Redirect error messages to logfile. */
		if ((fp = fopen(PATH_DSBMD_LOG, "a+")) == NULL)
			err(EXIT_FAILURE, "fopen()");
		(void)setvbuf(fp, NULL, _IOLBF, 0);
		err_set_file(fp);
	} else
		lockpidfile();
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
		if (strcmp(dp->d_name, ".")  == 0 ||
		    strcmp(dp->d_name, "..") == 0)
			continue;
		if (lstat(dp->d_name, &sb) == -1) {
			logprint("stat(%s)", dp->d_name);
			continue;
		}
		if (strncmp(dp->d_name, "ugen", 4) == 0)
			add_device(dp->d_name);
		else if (S_ISLNK(sb.st_mode)) { 
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
				add_device(lvmpath);
			}
			(void)closedir(dirp2);
		} else if (!S_ISDIR(sb.st_mode))
			add_device(dp->d_name);
	}
	(void)closedir(dirp);
	if (chdir("/") == -1)
		err(EXIT_FAILURE, "chdir(/)");
	/* Connect to devd. */
	if ((dsock = devd_connect()) == -1)
		err(EXIT_FAILURE, "Couldn't connect to %s", PATH_DEVD_SOCKET);

	/* Open the listening socket for the clients. */
        (void)unlink(PATH_DSBMD_SOCKET);
	if ((lsock = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1)
		err(EXIT_FAILURE, "socket()");
	(void)memset((char *)&s_addr, 0, sizeof(s_addr));
	(void)memcpy(s_addr.sun_path, PATH_DSBMD_SOCKET,
	    strlen(PATH_DSBMD_SOCKET));
	s_addr.sun_family = AF_LOCAL;
	if (bind(lsock, (struct sockaddr *)&s_addr, sizeof(s_addr)) == -1)
		err(EXIT_FAILURE, "bind()");
	if (chmod(PATH_DSBMD_SOCKET, SOCKET_MODE) == -1)
		err(EXIT_FAILURE, "chmod(%s)", PATH_DSBMD_SOCKET);
	if (listen(lsock, dsbcfg_getval(cfg, CFG_MAX_CLIENTS).integer) == -1)
		err(EXIT_FAILURE, "listen()");
	/*
	 * Make the listening socket non blocking in order to protect the
	 * server from certain DoS attacks.
	 */
	if ((sflags = fcntl(lsock, F_GETFL)) == -1)
		err(EXIT_FAILURE, "fcntl()");
	sflags |= O_NONBLOCK;
	if (fcntl(lsock, F_SETFL, sflags) == -1)
		err(EXIT_FAILURE, "fcntl()");

	if (polliv <= 0)
		polling = false;
	else
		polling = true;

	/* Min. time interval for select() */
	minsecs = mntchkiv < polliv ? mntchkiv : polliv;

	FD_ZERO(&allset);
	FD_SET(lsock, &allset); FD_SET(dsock, &allset);

	maxfd = dsock > lsock ? dsock : lsock;

	/* Main loop. */
	for (polltime = mntchktime = 0;;) {
		rset = allset;
		tv.tv_sec = minsecs; tv.tv_usec = 0;
		if (time(NULL) - mntchktime >= mntchkiv) 
			mntchktime = poll_mntbl();
		if (polling && difftime(time(NULL), polltime) >= polliv)
			polltime = do_poll();
		switch (select(maxfd + 1, &rset, NULL, NULL, &tv)) {
		case -1:
			if (errno == EINTR)
				continue;
			err(EXIT_FAILURE, "select()");
			/* NOTREACHED */
		case 0:
			if (polling && difftime(time(NULL), polltime) >= polliv)
				polltime = do_poll();
			if (time(NULL) - mntchktime >= mntchkiv) 
				mntchktime = poll_mntbl();
			continue;
		}
		if (FD_ISSET(dsock, &rset)) {
			/* New devd event. */
			while ((ev = read_devd_event(dsock, &e)) != NULL)
				process_devd_event(ev);
			if (e == SOCK_ERR_CONN_CLOSED) {
				/* Lost connection to devd. */
				FD_CLR(dsock, &allset);
				(void)close(dsock);
				logprintx("Lost connection to devd. " \
				    "Reconnecting ...");
				if ((dsock = devd_connect()) == -1) {
					logprintx("Connecting to devd " \
					    "failed. Giving up.");
					exit(EXIT_FAILURE);
				}
				maxfd = dsock > lsock ? dsock : lsock;
				FD_SET(dsock, &allset);
			} else if (e == SOCK_ERR_IO_ERROR)
				err(EXIT_FAILURE, "read_devd_event()");
		} 
		if (FD_ISSET(lsock, &rset)) {
			/* A client has connected. */
			if ((cli = process_connreq(lsock)) != NULL) {
				maxfd = maxfd > cli->s ? maxfd : cli->s;
				FD_SET(cli->s, &allset);
			}
		}
		for (i = 0; i < nclients; i++) {
			if (FD_ISSET(clients[i]->s, &rset)) {
				int clisock = clients[i]->s;
				if (serve_client(clients[i]) == -1) {
					/* Disconnected */
					FD_CLR(clisock, &allset);
				}
			}
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
	cliprintbc(NULL, "S");
	exit(EXIT_SUCCESS);
}

static void
lockpidfile()
{
	/* Check if deamon is already running. */
	if ((lockfp = fopen(PATH_PID_FILE, "r+")) == NULL) {
		if (errno != ENOENT)
			err(EXIT_FAILURE, "fopen(%s)", PATH_PID_FILE);
		/* Not running - Create the PID/lock file. */
		if ((lockfp = fopen(PATH_PID_FILE, "w")) == NULL) {
			err(EXIT_FAILURE, "couldn't create pid file %s",
			    PATH_PID_FILE);
		}
	}
	if (lockf(fileno(lockfp), F_TLOCK, 0) == -1) {
		if (errno == EAGAIN) {
			/* Daemon already running. */
			errx(EXIT_FAILURE, "%s is already running.", PROGRAM);
		} else
			err(EXIT_FAILURE, "flock()");
	}
	/* Write our PID to the PID/lock file. */
	(void)fprintf(lockfp, "%d", getpid());
	(void)fflush(lockfp);
	(void)ftruncate(fileno(lockfp), ftell(lockfp));
}

static sdev_t *
lookup_dev(const char *dev)
{
	int i;

	dev = devbasename(dev);
	for (i = 0; i < ndevs; i++) {
		if (strcmp(dev, devbasename(devs[i]->dev)) == 0)
			return (devs[i]);
	}
	return (NULL);
}

static client_t *
add_client(int socket)
{
	int	      n, saved_errno;
	char	      **p;
	uid_t	      uid;
	gid_t	      gid, gids[24];
	client_t      **cv, *cp;
	static int    id = 1;
	struct group  *grp;
	struct passwd *pw;

	cp = NULL; errno = 0;
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
		char msg[64];

		(void)snprintf(msg, sizeof(msg) - 1, "E:code=%d\n",
		    ERR_PERMISSION_DENIED);
		(void)send_string(socket, msg);
		(void)close(socket);
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
	cp->s	 = socket;
	cp->id	 = id++;
	cp->uid	 = uid;
	cp->slen = cp->rd = 0;
	cp->overflow = false;

	/* 
	 * Send the client the current list of mountable devs.
	 */
	for (n = 0; n < ndevs; n++) {
		if (devs[n]->visible)
			notify(cp, devs[n], true);
	}
	/* Terminate device list output. */
	cliprint(cp, "=");
	nclients++;
	logprintx("Client with UID %d connected", uid);

	return (cp);
error:
	saved_errno = errno;
	if (cp != NULL)
		free(cp->gids);
	free(cp);
	(void)close(socket);
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
	(void)close(cli->s); free(cli->gids);
	free(cli);
	
	for (; i < nclients - 1; i++)
		clients[i] = clients[i + 1];
	nclients--;
}

static bool
has_line(client_t *cli)
{
	return (cli->slen > 0 ? true : false);
}

/*
 * Return a value > 0 if a newline terminated string is available.
 * Return 0 if there is no new line terminated string available.
 * Return -1 if an error occured, or the connection was terminated.
 */
static int
client_readln(client_t *cli, int *error)
{
	int    i, n;
	bool   badchar;
	size_t bufsz = sizeof(cli->buf) - 1;

	*error = n = 0; badchar = false;
	while (cli->slen > 0 ||
	    ((n = read(cli->s, cli->buf + cli->rd, bufsz - cli->rd)) > 0)) {
		cli->rd += n;

		if (cli->slen > 0) {
			(void)memmove(cli->buf, cli->buf + cli->slen,
			    cli->rd - cli->slen);
		}
		cli->rd  -= cli->slen;
		cli->slen = 0;
		for (i = 0; i < cli->rd && cli->buf[i] != '\n'; i++) {
			if (!isprint(cli->buf[i]))
				badchar = true;
		}
		if (i < cli->rd) {
			cli->buf[i] = '\0';
			cli->slen = i + 1;
			if (cli->overflow || badchar) {
				if (cli->overflow) {
					cli->overflow = false;
					cliprint(cli, "E:code=%d\n",
					    ERR_STRING_TOO_LONG);
				}
				if (badchar) {
					cliprint(cli, "E:code=%d\n",
					    ERR_BAD_STRING);
					badchar = false;
				}
			} else
				return (1);
		} else if (cli->rd == bufsz) {
			/* Line too long. Ignore all bytes until next '\n'. */
			cli->overflow = true; cli->rd = 0;
		}
		n = 0;
	}
	if (n == 0 || (n < 0 && errno == ECONNRESET)) {
		/* Lost connection */
		*error = SOCK_ERR_CONN_CLOSED;
		return (-1);
	} else {
		/* n < 0 */
		if (errno == EAGAIN || errno == EINTR) {
			/* Just retry */
			return (0);
		} else
			*error = SOCK_ERR_IO_ERROR;
	}
	cli->slen = cli->rd = 0;

	return (-1);
}

static client_t *
process_connreq(int ls)
{
	int cs;
	client_t	   *cli;
	socklen_t	   clen;
	struct sockaddr_un c_addr;

	cs = accept(ls, (struct sockaddr *)&c_addr, &clen);
	if (cs == -1) {
		switch (errno) {
		case EINTR: case EWOULDBLOCK: case ECONNABORTED:
			return (NULL);
		default:
			err(EXIT_FAILURE, "accept()");
		}
	}
	if ((cli = add_client(cs)) == NULL) {
		if (errno != 0)
			logprint("add_client()");
		return (NULL);
	}
	return (cli);
}

static char *
read_devd_event(int s, int *error)
{
	int  i, n;
	static char *lnbuf = NULL;
	static int rd = 0, bufsz = 0, slen = 0;

	if (lnbuf == NULL) {
		if ((lnbuf = malloc(_POSIX2_LINE_MAX)) == NULL)
			return (NULL);
		bufsz = _POSIX2_LINE_MAX;
	}

	*error = n = 0;
	do {
		rd += n;
		if (slen > 0)
			(void)memmove(lnbuf, lnbuf + slen, rd - slen);
		rd  -= slen;
		slen = 0;
		for (i = 0; i < rd && lnbuf[i] != '\n'; i++)
			;
		if (i < rd) {
			lnbuf[i] = '\0'; slen = i + 1;
			if (slen == bufsz)
				slen = rd = 0;
			return (lnbuf);
		}
		if (rd == bufsz - 1) {
			lnbuf = realloc(lnbuf, bufsz + _POSIX2_LINE_MAX);
			if (lnbuf == NULL)
				err(EXIT_FAILURE, "realloc()");
			bufsz += 64;
		}
	} while ((n = read(s, lnbuf + rd, bufsz - rd - 1)) > 0);

	if (n < 0) {
		if (errno == EAGAIN || errno == EINTR) {
			/* Just retry */
			return (NULL);
		}
	}
	if (errno == 0 || errno == ECONNRESET)
		*error = SOCK_ERR_CONN_CLOSED;
	else
		*error = SOCK_ERR_IO_ERROR;
	/* Error or lost connection */
	slen = rd = 0;

	return (NULL);
}

static void
process_devd_event(char *ev)
{
	sdev_t *devp;

	if (ev[0] != '!')
		return;
	parse_devd_event(ev + 1);
	if (strcmp(devdevent.system, "DEVFS") != 0 ||
	    strcmp(devdevent.subsystem, "CDEV") != 0)
		return;
	if (strcmp(devdevent.type, "CREATE") == 0) {
		add_device(devdevent.cdev);
	} else if (strcmp(devdevent.type, "DESTROY") == 0) {
		if ((devp = lookup_dev(devdevent.cdev)) == NULL)
			return;
		/*
		 * Do not delete cd devices.
		 */
		if (devp->iface->type != IF_TYPE_CD)
			del_device(devp);
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
add_to_pollqueue(sdev_t *devp)
{
	int   i, len;
	char *p;

	for (p = devp->dev; !isdigit(*p); p++)
		;
	if (p[1] == '\0')
		len = strlen(devp->dev);
	else {
		if ((p[1] == 's' || p[1] == 'p') && isdigit(p[2])) {
			/* Do not add slices. */
			return;
		}
		len = p - devp->dev + 1;
	}
	for (i = 0; i < queuesz; i++) {
		if (strncmp(devp->dev, pollqueue[i]->dev, len) == 0)
			return;
	}
	if ((pollqueue = realloc(pollqueue,
	    sizeof(sdev_t *) * (queuesz + 1))) == NULL)
		err(EXIT_FAILURE, "realloc()");
	pollqueue[queuesz] = devp;
	pollqueue[queuesz]->has_media = has_media(devp->dev);
	queuesz++;
}

static void
del_from_pollqueue(sdev_t *devp)
{
	int i;

	for (i = 0; i < queuesz &&  devp != pollqueue[i]; i++)
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
	char   buf[16 * 1024];
	bool   media;
	off_t  size;
	size_t blksz;

	if ((fd = open(dev, O_RDONLY | O_NONBLOCK)) == -1)
		return (false);
	size  = g_mediasize(fd);
	blksz = g_sectorsize(fd);
	errno = 0;
	if ((int)size == -blksz || (int)size == -1)
		media = false;
	else if (read(fd, buf, blksz > sizeof(buf) ? sizeof(buf) : blksz) == -1)
		media = false;
	else
		media = true;
	(void)close(fd);

	return (media);
}

static time_t
do_poll()
{
	sdev_t *devp;

	while ((devp = media_changed()) != NULL)
		update_device(devp);
	return (time(NULL));
}

/*
 * Return a pointer to the next device whose media changed.
 */
static sdev_t *
media_changed()
{
	static int i = 0;

	for (i = i >= queuesz ? 0 : i; i < queuesz; i++) {
		if (has_media(pollqueue[i]->dev)) {
			if (!pollqueue[i]->has_media) {
				/* Media was inserted */
				pollqueue[i]->has_media = true;
				return (pollqueue[i++]);
			}
		} else if (pollqueue[i]->has_media) {
			/* Media was removed */
			pollqueue[i]->has_media = false;
			return (pollqueue[i++]);
		}
	}
	return (NULL);
}

static void
update_device(sdev_t *devp)
{
	char *p;

	if (devp->has_media) {
		/* Media inserted. */
		free(devp->name); devp->name = NULL;
		if (devp->iface->type == IF_TYPE_CD) {
			devp->st = get_storage_type(devp->dev);
			if (devp->st == NULL)
				return;
			switch (devp->st->type) {
			case ST_CDDA:
			case ST_SVCD:
			case ST_VCD:
				devp->visible = true;
				notifybc(devp, true);
				return;
			case ST_DATACD:
			case ST_DVD:
				devp->fs = getfs(devp->dev);
				if (devp->fs == NULL)
					return;
				break;
			default:
				break;
			}
		} else if ((devp->fs = getfs(devp->dev)) == NULL) {
			return;
		}
		if ((p = get_label(devp->dev, devp->fs->name)) != NULL) {
			if ((devp->name = strdup(p)) == NULL)
				err(EXIT_FAILURE, "strdup()");
		} else if ((devp->name = strdup(devbasename(devp->dev))) == NULL)
			err(EXIT_FAILURE, "strdup()");
		devp->visible = true;
		notifybc(devp, true);
	} else {
		/* Media removed. */
		devp->visible = false;

		if (devp->fs != NULL) { 
			notifybc(devp, false);
			devp->fs = NULL;
			if (getmntpt(devp) != NULL) {
				/*
				 * Device was ejected without unmounting it
				 * first.
				 * Unmount device and remove mount point.
				 */
				(void)unmount(devp->mntpt, MNT_FORCE);
				rmntpt(devp->mntpt);
				free(devp->mntpt);
				devp->mntpt   = NULL;
				devp->mounted = false;
				/* Restore ownership in case we changed it. */
				(void)change_owner(devp, devp->owner);
			}
		} else {
			if (devp->st == NULL)
				return;
			switch (devp->st->type) {
			case ST_CDDA:
			case ST_SVCD:
			case ST_VCD:
				notifybc(devp, false);
				return;
			default:
				return;
			}

		}
	}
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
 * We consider a device not mountable if it appears in /etc/fstab without
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
	struct passwd *pw;

	errno = 0;
	if ((pw = getpwuid(euid)) == NULL) {
		if (errno != 0)
			logprint("getpwuid(%u)", euid);
		else
			logprintx("Couldn't find user with UID %u", euid);
		return;
	}
	endpwent();
	if (geteuid() == 0) {
		if (initgroups(pw->pw_name, pw->pw_gid) == -1)
			err(EXIT_FAILURE, "initgroups()");
	}
	if (setegid(egid) == -1)
		logprint("setegid(%u)", egid);
	if (seteuid(euid) == -1)
		logprint("seteuid(%u)", euid);
}

static void
setuserenv(uid_t uid)
{
	login_cap_t   *lc;
	struct passwd *pw;

	errno = 0;
	if ((pw = getpwuid(uid)) == NULL) {
		if (errno != 0)
			logprint("getpwuid(%u)", uid);
		else
			logprintx("Couldn't find user with UID %u", uid);
		return;
	}
	endpwent();
	if ((lc = login_getpwclass(pw)) == NULL)
		err(EXIT_FAILURE, "login_getpwclass()");
	if (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETALL) == -1)
		err(EXIT_FAILURE, "setusercontext()");
}

static void
restoreids()
{
	struct passwd *pw;

	errno = 0;
	if ((pw = getpwuid(getuid())) == NULL) {
		if (errno != 0)
			logprint("getpwuid(%u)", getuid());
		else
			logprintx("Couldn't find user with UID %u", getuid());
		exit(EXIT_FAILURE);
	}
	endpwent();
	switcheids(getuid(), getgid());
}

static int
change_owner(sdev_t *dev, uid_t owner)
{
	char *path;

	path = dev->iface->type == IF_TYPE_LVM ? dev->realdev : dev->dev;
	if (chown(path, owner, dev->group) == -1) {
		logprint("chown(%s)", path);
		return (-1);
	}
	return (0);
}

static int
ssystem(uid_t uid, const char *cmd)
{
	int	 i, procmaxwait, sc, status, sigs[2] = { SIGTERM, SIGKILL };
	pid_t	 pid, ret;
	sigset_t sigmask, savedmask;

	procmaxwait = dsbcfg_getval(cfg, CFG_PROCMAXWAIT).integer;
	errno = 0;
	/* Block SIGCHLD */
	(void)sigemptyset(&sigmask); (void)sigaddset(&sigmask, SIGCHLD);
	(void)sigprocmask(SIG_BLOCK, &sigmask, &savedmask);

	switch ((pid = vfork())) {
	case -1:
		err(EXIT_FAILURE, "vfork()");
		/* NOTREACHED */
	case  0:
		setuserenv(uid);
		/* Restore old signal mask */
		(void)sigprocmask(SIG_SETMASK, &savedmask, NULL);
		execl(_PATH_BSHELL, _PATH_BSHELL, "-c", cmd, NULL);
		_exit(255);
		/* NOTREACHED */
	default:
		/* Restore old signal mask */
		(void)sigprocmask(SIG_SETMASK, &savedmask, NULL);
		break;
	}
	for (i = errno = 0; i < procmaxwait; errno = 0) {
		ret = waitpid(pid, &status, WEXITED | WNOHANG);
		if (ret == (pid_t)-1 && errno == EINTR)
			continue;
		else if (ret == (pid_t)-1)
			err(EXIT_FAILURE, "waitpid()");
		else if (ret == pid)
			return (status == 255 ? -1 : status);
		(void)sleep(1);
		i++;
	}
	if (i >= procmaxwait) {
		/* Kill blocking process */
		logprintx("Killing blocking process %u ...", pid);
		for (sc = 0; sc < sizeof(sigs) / sizeof(int); sc++) {
			logprintx("Sending %s to %u ...",
			    sc == 0 ? "SIGTERM" : "SIGKILL", pid);
			(void)kill(pid, sigs[sc]);
			for (i = errno = 0; i < 5; errno = 0) {
				ret = waitpid(pid, &status, WEXITED | WNOHANG);
				if (ret == (pid_t)-1 && errno == EINTR)
					continue;
				else if (ret == (pid_t)-1)
					err(EXIT_FAILURE, "waitpid()");
				else if (ret == pid)
					return (status == 255 ? -1 : status);
				(void)sleep(1);
				i++;
			}
		}
	}
	if (errno != 0)
		return (-1);
	return (status == 255 ? -1 : status);
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
mount_device(client_t *cli, sdev_t *devp)
{
	int	   i, j, len;
	char	   mopts[512], romopts[512], num[12], *mntpath, *p, *q;
	const char *op;

	if (!devp->has_media) {
		cliprint(cli, "E:command=mount:code=%d", ERR_NO_MEDIA);
		return (ERR_NO_MEDIA);
	}
	if (devp->fs == NULL) {
		cliprint(cli, "E:command=mount:code=%d",
		    ERR_UNKNOWN_FILESYSTEM);
		return (ERR_UNKNOWN_FILESYSTEM);
	}
	if (devp->fs->uopts != NULL)
		op = devp->fs->uopts;
	else
		op = devp->fs->dopts;
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

	/* Check if the device is already mounted. */
	if ((devp->mounted && devp->cmd_mounted) || getmntpt(devp) != NULL) {
		cliprint(cli, "E:command=mount:code=%d", ERR_ALREADY_MOUNTED);
		return (ERR_ALREADY_MOUNTED);
	}
	mntpath = mkmntpt(devp);
	if (chown(mntpath, cli->uid, cli->gids[0]) == -1)
		err(EXIT_FAILURE, "chown(%s)", mntpath);
	if (dsbcfg_getval(cfg, CFG_USERMOUNT).boolean && usermount_set()) {
		/*
		 * Change the owner of the device so that the user
		 * can mount it.
		 */
		if (change_owner(devp, cli->uid) == -1) {
			rmntpt(mntpath); free(mntpath);
			cliprint(cli, "E:command=mount:code=%d", errno);
			return (-1);
		}
	}
	errno = 0;

	if (devp->fs->mntcmd != NULL || (devp->fs->mntcmd_u != NULL &&
	    dsbcfg_getval(cfg, CFG_USERMOUNT).boolean && usermount_set())) {
		/*
		 * Execute the userdefined mount command.
		 */
		return (exec_mntcmd(cli, devp, mntpath));
	}
	if (!mymount(devp->fs->name, mntpath, devp->dev, mopts, cli->uid,
	    cli->gids[0]) ||
	    !mymount(devp->fs->name, mntpath, devp->dev, romopts, cli->uid,
	    cli->gids[0])) {
		free(mntpath);
		if (getmntpt(devp) == NULL)
			err(EXIT_FAILURE, "getmntpt()");
		devp->mounted = true;
		devp->cmd_mounted = false;
		cliprint(cli, "O:command=mount:dev=%s:mntpt=%s", devp->dev,
		    devp->mntpt);
		cliprintbc(cli, "M:dev=%s:mntpt=%s", devp->dev, devp->mntpt);
		logprintx("Device %s mounted on %s by UID %d", devp->dev,
		    devp->mntpt, cli->uid);
		return (0);
	}
	cliprint(cli, "E:command=mount:code=%d", errno);
	logprint("Mounting of %s by UID %d failed", devp->dev, cli->uid);
	(void)change_owner(devp, devp->owner);
	rmntpt(mntpath);
	free(mntpath);

	return (0);
}

static int
exec_mntcmd(client_t *cli, sdev_t *devp, char *mntpath)
{
	int	    error;
	uid_t	    uid;
	gid_t	    gid;
	char	    num[12];
	const char *mntcmd;

	if (dsbcfg_getval(cfg, CFG_USERMOUNT).boolean && usermount_set()) {
		uid = cli->uid;
		gid = cli->gids[0];
		mntcmd = devp->fs->mntcmd_u;
	} else {
		uid = 0;
		gid = 0;
		mntcmd = devp->fs->mntcmd;
	}
	(void)snprintf(num, sizeof(num), "%u", cli->uid);
	(void)setenv(ENV_UID, num, 1);
	(void)snprintf(num, sizeof(num), "%u", cli->gids[0]);
	(void)setenv(ENV_GID, num, 1);
	(void)setenv(ENV_DEV, devp->dev, 1);
	(void)setenv(ENV_LABEL, devp->name, 1);
	(void)setenv(ENV_FILESYSTEM, devp->fs->name, 1);
	(void)setenv(ENV_MNTPT, mntpath, 1);
	if (devp->iface->type == IF_TYPE_UGEN) {
		(void)setenv(ENV_USB_PORT,
		    ugen_to_gphoto_port(devbasename(devp->dev)), 1);
	}
	if ((error = ssystem(uid, mntcmd)) == 0 && !is_mntpt(mntpath)) {
		cliprint(cli, "E:command=mount:code=%d", ERR_UNKNOWN_ERROR);
		logprintx("Command '%s' executed by UID %d returned "	  \
			  "0, but the mount point %s could not be found " \
			  "in the mount table", mntcmd, cli->uid, mntpath);
		(void)change_owner(devp, devp->owner);
		rmntpt(mntpath);
		free(mntpath);
	} else if (is_mntpt(mntpath)) {
		devp->mntpt = mntpath;
		devp->mounted = true;
		devp->cmd_mounted = true;
		cliprint(cli, "O:command=mount:dev=%s:mntpt=%s", devp->dev,
		    devp->mntpt);
		cliprintbc(cli, "M:dev=%s:mntpt=%s", devp->dev, devp->mntpt);
		logprintx("Device %s mounted on %s by UID %d", devp->dev,
		    devp->mntpt, cli->uid);
	} else {
		cliprint(cli, "E:command=mount:code=%d:mntcmderr=%d",
		    ERR_MNTCMD_FAILED, error);
		logprint("Command %s executed by UID %d " \
			 "failed with code %d", mntcmd, cli->uid,
			 errno != 0 ? errno : error);
		rmntpt(mntpath);
		free(mntpath);
		(void)change_owner(devp, devp->owner);
	}
	return (error);
}

/*
 * Unmounts a device. If 'force'  is  true, unmounting of the device will be
 * enforced,  even  if  the  device is busy. If 'eject' is true, no command
 * reply  code  will  be send to the client. This is used for eject_media()
 * to prevent dsbmd  from sending two reply codes (one for unmount, and one
 * for eject) to the client.
 */
static int
unmount_device(client_t *cli, sdev_t *devp, bool force, bool eject)
{

	if (devp->iface->type != IF_TYPE_FUSE &&
	    (!devp->mounted && devp->cmd_mounted) && getmntpt(devp) == NULL) {
		if (!eject) {
			cliprint(cli, "E:command=unmount:code=%d",
			    ERR_NOT_MOUNTED);
		}
		return (ERR_NOT_MOUNTED);
	} else if (!devp->mounted) {
		if (!eject) {
			cliprint(cli, "E:command=unmount:code=%d",
			    ERR_NOT_MOUNTED);
		}
		return (ERR_NOT_MOUNTED);
	}
	if (unmount(devp->mntpt, force ? MNT_FORCE : 0) == -1) {
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
		    "failed", devp->dev, devp->mntpt, cli->uid);
		return (errno);
	}
	/* Unmounting was successfull. */
	if (!eject) {
		cliprint(cli, "O:command=unmount:dev=%s:mntpt=%s", devp->dev,
		    devp->mntpt);
	}
	/*
	 * If a device is mounted and the client sent an eject command, it
	 * could happen that the unmount was successful, but ejecting failed.
	 * With some devices, CAM reports ejecting the media was successful,
	 * albeit it wasn't. So in case unmounting was initiated by the eject
	 * command, we send the client an info message informing them that the
	 * device was unmounted.
	 */
	cliprintbc(eject ? NULL : cli, "U:dev=%s:mntpt=%s",
	    devp->dev, devp->mntpt);
	logprintx("Device %s unmounted from %s by UID %d", devp->dev,
	    devp->mntpt, cli->uid);
	rmntpt(devp->mntpt);
	free(devp->mntpt); devp->mntpt = NULL;
	devp->mounted = false;
	(void)change_owner(devp, devp->owner);
	if (devp->iface->type == IF_TYPE_FUSE)
		del_device(devp);
	sleep(1);

	return (0);
}

static char *
mkmntpt(const sdev_t *devp)
{
	char	    *mntpath;
	size_t	    pathlen, namelen, devlen;
	const char  *mntdir, *p;
	struct stat sb;

	/* Create the mount point */
	if ((mntdir = dsbcfg_getval(cfg, CFG_MNTDIR).string) == NULL)
		errx(EXIT_FAILURE, "mount_dir undefined");
	if (mkdir(mntdir, MNTDIRPERM) == -1) {
		if (errno != EEXIST)
			err(EXIT_FAILURE, "mkdir(%s)", mntdir);
	}
	/* Skip directory part in case of Linux LV */
	if ((p = strchr(devp->name, '/')) != NULL)
		p++;
	else
		p = devp->name;

	pathlen  = strlen(mntdir);
	namelen  = strlen(p);
	devlen	 = strlen(devbasename(devp->dev));
	pathlen += (namelen < devlen ? devlen : namelen) + 2;

	if ((mntpath = malloc(pathlen)) == NULL)
		err(EXIT_FAILURE, "malloc()");
	(void)sprintf(mntpath, "%s/%s", mntdir, p);

	if (stat(mntpath, &sb) == -1 && errno != ENOENT)
		err(EXIT_FAILURE, "stat(%s)", mntpath);
	else if (errno == ENOENT) {
		if (mkdir(mntpath, MNTPTMODE) == -1)
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
			if (strcmp(devbasename(devp->dev), devp->name) != 0) {
				/*
				 * If  the  device's  devname is != its vol ID
				 * try   to   create   a   mount   path   with
				 * <mntdir>/<devname>. If that also fails, try
				 * to create a random mount path.
				 */
				(void)snprintf(mntpath, MNAMELEN, "%s/%s",
				    mntdir, devbasename(devp->dev));
				if (mkdir(mntpath, MNTPTMODE) == -1) {
					if (errno != EEXIST)
						err(EXIT_FAILURE, "mkdir(%s)",
						    mntpath);
				} else
					return (mntpath);
			}
			/*
			 * No luck so far. Create a random mount point
			 */
			(void)snprintf(mntpath, MNAMELEN, "%s/%s.XXXX",
			    mntdir, devbasename(devp->dev));
			if (mkdtemp(mntpath) == NULL)
				err(EXIT_FAILURE, "mkdtemp(%s)", mntpath);
		} else {
			/* Recreate directory */
			if (mkdir(mntpath, MNTPTMODE) == -1)
				err(EXIT_FAILURE, "mkdir(%s)", mntpath);
		}
	}
	return (mntpath);
}

/*
 * Looks up the given device's mount point in the mount table.
 */
static char *
getmntpt(sdev_t *devp)
{
	int	      i, n;
	const char    *p, *q;
	struct statfs *mb;

	errno = 0;
	if ((n = getmntinfo(&mb, MNT_WAIT)) == -1)
		err(EXIT_FAILURE, "getmntinfo()");
	p = devbasename(devp->dev);
	for (i = 0; i < n; i++) {
		q = devbasename(mb[i].f_mntfromname);
		if (strcmp(p, q) == 0) {
			/* The device was mounted using its device name. */
			if (devp->mntpt != NULL &&
			    strcmp(devp->mntpt, mb[i].f_mntonname) == 0)
				return (devp->mntpt);
			free(devp->mntpt);
			if ((devp->mntpt = strdup(mb[i].f_mntonname)) == NULL)
				err(EXIT_FAILURE, "strdup()");
			return (devp->mntpt);
		}
		/* Check if the device was mounted using its glabel. */
		if (match_glabel(devp, q)) {
			if (devp->mntpt != NULL &&
			    strcmp(devp->mntpt, mb[i].f_mntonname) == 0)
				return (devp->mntpt);
			free(devp->mntpt);
			if ((devp->mntpt = strdup(mb[i].f_mntonname)) == NULL)
				err(EXIT_FAILURE, "strdup()");
			return (devp->mntpt);
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
	static char  *p, *name = NULL;
	static size_t len = 0;

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
get_optical_disk_type(const char *path)
{
	int    fd, lbs, seqnum, dirtblpos, dirtblsz, type, reclen;
	int    i, len, sector, offset, saved_errno, namelen, pbs;
	char   *buf, *p;
	bool   has_video_ts, has_mpeg2, has_mpegav, has_svcd, has_vcd;
	off_t  msz;
	struct ioc_toc_header tochdr;
        struct iso_directory_record *dp;
	struct iso_primary_descriptor *ip;
	struct ioc_read_toc_single_entry tocent;

	if (!has_media(path))
		return (-1);
	buf = NULL; type = ST_UNKNOWN;
	if ((fd = open(path, O_RDONLY)) == -1) {
		logprint("open()");
		goto error;
	}
	/* Check whether the device has a valid media. */
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
		type = ST_CDDA;
		goto done;
	} else
		type = ST_UNKNOWN;
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
	type = ST_DATACD;
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
	while (type == ST_DATACD && dirtblsz > 0) {
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
			type = ST_DVD;
		else if (has_mpeg2 && has_svcd)
			type = ST_SVCD;
		else if (has_mpegav && has_vcd)
			type = ST_VCD;
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

const storage_type_t *
st_from_type(uint8_t type)
{
	int i;

	for (i = 0; i < sizeof(storage_types) / sizeof(storage_type_t); i++) {
		if (storage_types[i].type == type)
			return (&storage_types[i]);
	}
	return (NULL);
}

const iface_t *
iface_from_type(uint8_t type)
{
	int i;

	for (i = 0; i < sizeof(interfaces) / sizeof(iface_t); i++) {
		if (interfaces[i].type == type)
			return (&interfaces[i]);
	}
	return (NULL);
}

const iface_t *
iface_from_name(const char *name)
{
	int	i;
	regex_t preg;

	for (i = 0; i < sizeof(interfaces) / sizeof(iface_t); i++) {
	        if (interfaces[i].re == NULL)
			continue;
		if (regcomp(&preg, interfaces[i].re, REG_EXTENDED))
               		logprintx("regcomp(%s) failed", interfaces[i].re);
		else if (regexec(&preg, name, 0, 0, 0) == 0)
			return (&interfaces[i]);
	}
        return (NULL);
}

static int
devstat(const char *dev, struct stat *sb)
{
	char *path;

	path = devpath(dev);
	if (stat(path, sb) == -1) {
		logprint("stat(%s)", path);
		return (-1);
	}
	return (0);
}

static const storage_type_t *
get_storage_type(const char *devname)
{
	int   type;
	char  *realdev;
	const iface_t *iface;
	const char *base;

	base = devbasename(devname);
	iface = iface_from_name(base);

	if (iface == NULL)
		return NULL;
	switch (iface->type) {
	case IF_TYPE_CD:
		if (has_media(devname)) {
			if ((type = get_optical_disk_type(devname)) == -1)
				return (NULL);
			if (type == ST_UNKNOWN)
				return (NULL);
			return (st_from_type(type));
		}
		return (NULL);
	case IF_TYPE_LVM:
		realdev = get_lvm_dev(base);
		return (get_storage_type(realdev));
	case IF_TYPE_DA:
		if ((type = get_da_storage_type(devname)) == -1)
			return (NULL);
		return (st_from_type(type));
	case IF_TYPE_UGEN:
		if ((type = get_ugen_type(base)) == -1)
			return (NULL);
		if (type == ST_MTP || type == ST_PTP)
			return (st_from_type(type));
		return (NULL);
	default:
		return (st_from_type(ST_HDD));
	}
	return (NULL);
}

static int
get_da_storage_type(const char *devname)
{
	int    u, type;
	char   var[sizeof("dev.umass.##.%location") + 1], buf[512], *disk, *p;
	size_t sz;
	struct cam_device *cd;

 	disk = get_diskname(devname);
	if ((cd = cam_open_device(disk, O_RDWR)) == NULL) {
		logprint("cam_open_device(%s): %s", disk, cam_errbuf);
		return (-1);
	}
	if (strncmp(cd->sim_name, "umass-sim", 9) != 0) {
		cam_close_device(cd);
		return (ST_HDD);
	}
	u = strtol(cd->sim_name + 9, NULL, 10);
	cam_close_device(cd);

	(void)snprintf(var, sizeof(var) - 1, "dev.umass.%d.%%location", u);

	sz = sizeof(buf) - 1;
	if (sysctlbyname(var, buf, &sz, NULL, 0) == -1) {
		logprint("sysctlbyname(%s)", var);
		return (-1);
	}
	for (p = buf; (p = strtok(p, "\t ")) != NULL; p = NULL) {
		if (strncmp(p, "ugen=", 5) == 0)
			break;
	}
	if (p == NULL)
		return (-1);
	p += 5;
	if ((type = get_ugen_type(p)) == -1)
		return (-1);
	return (type);
}

static sdev_t *
add_ptp_device(const char *ugen)
{
	int	    i, len;
	sdev_t	    *devp;
	const char  *dev;
	struct stat sb;

	dev = devbasename(ugen);
	/* Check if we already have this device. */
	len = strlen(dev);
	for (i = 0; i < ndevs; i++) {
		if (strcmp(dev, devs[i]->dev + sizeof(_PATH_DEV) - 1) == 0) {
			/* Device already exists. */
			return (NULL);
		}
	}
	if (devstat(ugen, &sb) == -1)
		return (NULL);
	if ((devp = malloc(sizeof(sdev_t))) == NULL)
		err(EXIT_FAILURE, "malloc()");
	if ((devp->dev = strdup(devpath(dev))) == NULL)
		err(EXIT_FAILURE, "strdup()");
	for (i = 0; i < nfstypes && fstype[i].id != PTPFS; i++)
		;
	devp->fs = &fstype[i];
	if ((devp->name = get_label(dev, devp->fs->name)) != NULL) {
		devp->name = strdup(devp->name);
		if (devp->name == NULL)
			err(EXIT_FAILURE, "strdup()");
	} else {
		devp->name = malloc(sizeof("Camera ()") + strlen(dev) + 1);
		if (devp->name == NULL)
			err(EXIT_FAILURE, "malloc()");
		(void)sprintf(devp->name, "Camera (%s)", dev);
	}
	devp->owner	  = sb.st_uid;
	devp->group	  = sb.st_gid;
	devp->st	  = st_from_type(ST_PTP);
	devp->iface	  = iface_from_name(dev);
	devp->model	  = NULL;
	devp->realdev	  = NULL;
	devp->glabel[0]   = NULL;
	devp->mounted     = false;
	devp->has_media   = true;
	devp->polling     = false;
	devp->ejectable	  = false;
	devp->visible	  = true;
	devp->mntpt	  = NULL;
	devp->cmd_mounted = false;
	devs = realloc(devs, sizeof(sdev_t *) * (ndevs + 1));
	if (devs == NULL)
		err(EXIT_FAILURE, "realloc()");
	devs[ndevs++] = devp;
	notifybc(devp, true);

	return (devp);
}

static sdev_t *
add_mtp_device(const char *ugen)
{
	int	    i, len;
	sdev_t	    *devp;
	const char  *dev;
	struct stat sb;

	dev = devbasename(ugen);
	/* Check if we already have this device. */
	len = strlen(dev);
	for (i = 0; i < ndevs; i++) {
		if (strcmp(dev, devs[i]->dev + sizeof(_PATH_DEV) - 1) == 0) {
			/* Device already exists. */
			return (NULL);
		}
	}
	if (devstat(ugen, &sb) == -1)
		return (NULL);
	if ((devp = malloc(sizeof(sdev_t))) == NULL)
		err(EXIT_FAILURE, "malloc()");
	if ((devp->dev = strdup(devpath(dev))) == NULL)
		err(EXIT_FAILURE, "strdup()");

	for (i = 0; i < nfstypes && fstype[i].id != MTPFS; i++)
		;
	devp->fs = &fstype[i];
	if ((devp->name = get_label(dev, devp->fs->name)) != NULL) {
		devp->name = strdup(devp->name);
		if (devp->name == NULL)
			err(EXIT_FAILURE, "strdup()");
	} else {
		devp->name = malloc(sizeof("Camera ()") + strlen(dev) + 1);
		if (devp->name == NULL)
			err(EXIT_FAILURE, "malloc()");
		(void)sprintf(devp->name, "MTP device (%s)", dev);
	}
	devp->owner	  = sb.st_uid;
	devp->group	  = sb.st_gid;
	devp->st	  = st_from_type(ST_MTP);
	devp->iface	  = iface_from_name(dev);
	devp->model	  = NULL;
	devp->realdev	  = NULL;
	devp->glabel[0]   = NULL;
	devp->mounted     = false;
	devp->has_media   = true;
	devp->polling     = false;
	devp->ejectable	  = false;
	devp->visible	  = true;
	devp->mntpt	  = NULL;
	devp->cmd_mounted = false;
	devs = realloc(devs, sizeof(sdev_t *) * (ndevs + 1));
	if (devs == NULL)
		err(EXIT_FAILURE, "realloc()");
	devs[ndevs++] = devp;
	notifybc(devp, true);

	return (devp);
}

static sdev_t *
add_fuse_device(const char *mntpt)
{
	int	   i;
	sdev_t	   *devp;
	const char *p;
	static int id = 0;

	if ((devp = malloc(sizeof(sdev_t))) == NULL)
		err(EXIT_FAILURE, "malloc()");
	/* Generate a fictive device name */
	if ((devp->dev = strdup("/dev/pseudo##")) == NULL)
		err(EXIT_FAILURE, "strdup()");
	(void)sprintf(devp->dev, "/dev/pseudo%02d", id++);
	/* Use the last part of mount point path for the name */
	for (p = strchr(mntpt, '\0'); *p != '/' && p != mntpt; p--)
		;
	if (*p == '/')
		p++;
	if ((devp->name = strdup(p)) == NULL)
		err(EXIT_FAILURE, "strdup()");
	for (i = 0; i < nfstypes && fstype[i].id != FUSEFS; i++)
		;
	devp->st	  = st_from_type(ST_FUSE);
	devp->fs	  = &fstype[i];
	devp->iface	  = iface_from_type(IF_TYPE_FUSE);
	devp->model	  = NULL;
	devp->realdev	  = NULL;
	devp->glabel[0]	  = NULL;
	devp->mounted	  = true;
	devp->has_media	  = true;
	devp->polling	  = false;
	devp->visible	  = true;
	devp->ejectable	  = false;
	devp->cmd_mounted = false;
	if ((devp->mntpt = strdup(mntpt)) == NULL)
		err(EXIT_FAILURE, "strdup()");
	devs = realloc(devs, sizeof(sdev_t *) * (ndevs + 1));
	if (devs == NULL)
		err(EXIT_FAILURE, "realloc()");
	devs[ndevs++] = devp;
	notifybc(devp, true);

	return (devp);
}

static sdev_t *
add_device(const char *devname)
{
	int	    len, i, j, speed, fd;
	char	    **v, *diskname, *path, *realdev;
	sdev_t	    *devp, dev = { 0 };
	const char  *p;
	struct stat sb;

	devname = devbasename(devname);

	/* Check if we already have this device. */
	len = strlen(devname);
	for (i = 0; i < ndevs; i++) {
		if (!strcmp(devname, devs[i]->dev + sizeof(_PATH_DEV) - 1)) {
			/* Device already exists. */
			return (NULL);
		}
	}
	if ((dev.iface = iface_from_name(devname)) == NULL)
		return (NULL);
	dev.polling = false;
	if ((dev.st = get_storage_type(devname)) != NULL) {
		if (dev.st->type == ST_USB_CARDREADER) {
			diskname = get_diskname(devname);
			/* Only poll disk device, not slices. */
			if (strcmp(diskname, devname) == 0)
				dev.polling = true;
		} else if (dev.st->type == ST_MTP)
			return (add_mtp_device(devname));
		else if (dev.st->type == ST_PTP)
			return (add_ptp_device(devname));
		else if (is_parted(devname) && !match_part_dev(devname, 0))
			/* Only add slices of partitioned disks. */
			return (NULL);
	} else if (dev.iface->type != IF_TYPE_CD)
		return (NULL);
	if (dev.iface->type == IF_TYPE_CD) {
		/* Ignore devices like 'cd0a' */
		p = strchr(devname, '\0') - 1;
		if (strchr("abcdefgh", *p) != NULL)
			return (NULL);
		dev.polling = true;
	} 
	if (dev.iface->type == IF_TYPE_LVM) {
		realdev = get_lvm_dev(devname);
		if (realdev == NULL)
			return (NULL);
		if ((dev.realdev = strdup(realdev)) == NULL)
			err(EXIT_FAILURE, "strdup()");
		if (devstat(realdev, &sb) == -1)
			return (NULL);
	} else if (devstat(devname, &sb) == -1)
		return (NULL);
	if (!is_mountable(devname))
		return (NULL);
	/* Get full path to device */
	path = devpath(devname);
	if ((dev.has_media = has_media(path)))
		dev.fs = getfs(path);
	else
		dev.fs = NULL;
	if (dev.fs == NULL && dev.has_media) {
		if (dev.st != NULL) {
			if (dev.st->type != ST_USB_CARDREADER &&
			    dev.iface->type != IF_TYPE_CD) {
				/* HDD/USB stick with unknown filesystem. */
				return (NULL);
			}
		}
	}
	if (dev.iface->type == IF_TYPE_DA || dev.iface->type == IF_TYPE_CD)
		dev.ejectable = true;
	else
		dev.ejectable = false;
	if ((devp = malloc(sizeof(sdev_t))) == NULL)
		err(EXIT_FAILURE, "malloc()");
	if ((devp->dev = strdup(path)) == NULL)
		err(EXIT_FAILURE, "strdup()");
	if (dev.fs != NULL && (p = get_label(devname, dev.fs->name)) != NULL) {
		if ((devp->name = strdup(p)) == NULL)
			err(EXIT_FAILURE, "strdup()");
	} else if ((devp->name = strdup(devname)) == NULL)
		err(EXIT_FAILURE, "strdup()");

	/*
	 * Get all glabels for this device. Drives with UFS can have more than
	 * one glabel: ufs/somename, or label/somename, and ufsid/id.
	 */
	for (i = j = 0; i < NGLBLPRFX; i++) {
		if ((p = get_geom_label(devname, glblprfx[i])) != NULL) {
			if ((devp->glabel[j++] = strdup(p)) == NULL)
				err(EXIT_FAILURE, "strdup()");
		}
	}
	/* Terminate glabel list. */
	devp->glabel[j]	= NULL;

	devp->owner	  = sb.st_uid;
	devp->group	  = sb.st_gid;
	devp->st	  = dev.st;
	devp->iface       = dev.iface;
	devp->fs	  = dev.fs;
	devp->mounted	  = false;
	devp->mntpt       = NULL;
	devp->polling	  = dev.polling;
	devp->realdev     = dev.realdev;
	devp->has_media   = dev.has_media;
	devp->visible	  = false;
	devp->ejectable   = dev.ejectable;
	devp->cmd_mounted = false;

	/* Set max. CD/DVD reading speed. */
	if (devp->iface->type == IF_TYPE_CD) {
		speed = dsbcfg_getval(cfg, CFG_CDRSPEED).integer * 177;
		if ((fd = open(devp->dev, O_RDWR)) != -1) {
			if (ioctl(fd, CDRIOCREADSPEED, &speed) == -1) {
				logprint("ioctl(%s, CDRIOCREADSPEED)",
				    devp->dev);
			}
			(void)close(fd);
		} else
			logprint("open(%s)", devp->dev);
	}
	(void)getmntpt(devp);
	if (devp->mntpt != NULL)
		devp->mounted = true;
	switch (devp->iface->type) {
	case IF_TYPE_DA:
	case IF_TYPE_CD:
	case IF_TYPE_ADA:
		devp->model = get_cam_modelname(devname);
		break;
	default:
		devp->model = NULL;
	}
	/* Ckeck if polling is undesirable for this device. */
	for (v = dsbcfg_getval(cfg, CFG_POLL_EXCEPTIONS).strings;
	    v != NULL && *v != NULL; v++) {
		if (devp->model == NULL)
			break;
		if (fnmatch(*v, devp->model, FNM_CASEFOLD) == 0)
			devp->polling = false;
	}
	if (devp->polling)
		add_to_pollqueue(devp);
	if (devp->has_media && devp->fs != NULL)
		devp->visible = true;
	else if (devp->has_media && devp->st != NULL) {
		switch (devp->st->type) {
		case ST_CDDA:
		case ST_SVCD:
		case ST_VCD:
			devp->visible = true;
			break;
		default:
			break;
		}
	}
	devs = realloc(devs, sizeof(sdev_t *) * (ndevs + 1));
	if (devs == NULL)
		err(EXIT_FAILURE, "realloc()");
	devs[ndevs++] = devp;
	if (devp->st == NULL)
		devp->visible = false;
	if (devp->visible)
		notifybc(devp, true);
	return (devp);
}

/*
 * Removes the given device object from the device list.
 */
static void
del_device(sdev_t *devp)
{
	int i, j;

	for (i = 0; i < ndevs && devp != devs[i]; i++)
		;
	if (i == ndevs)
		return;
	del_from_pollqueue(devs[i]);

	if (devs[i]->has_media && devs[i]->visible)
		notifybc(devs[i], false);
	/*
	 * Try to remove the mount table entry if the device was removed
	 * without unmounting it first.
	 */
	if (is_mntpt(devs[i]->mntpt)) {
		(void)unmount(devs[i]->mntpt, MNT_FORCE);
		(void)rmntpt(devs[i]->mntpt);
	}
	free(devs[i]->mntpt);
	free(devs[i]->dev);
	free(devs[i]->name);
	free(devs[i]->model);
	free(devs[i]->realdev);

	for (j = 0; j < NGLBLPRFX && devs[i]->glabel[j] != NULL; j++)
		free(devs[i]->glabel[j]);
	free(devs[i]);

	for (; i < ndevs - 1; i++)
		devs[i] = devs[i + 1];
	ndevs--;
}

static char *
ugen_to_gphoto_port(const char *ugen)
{
	int	    bus, addr;
	static char port[sizeof("usb:###,###") + 1];

	get_ugen_bus_and_addr(ugen, &bus, &addr);
	(void)snprintf(port, sizeof(port) - 1, "usb:%03d,%03d", bus, addr);

	return (port);
}

static int
get_ugen_type(const char *ugen)
{
	int  i, j, bus, addr, type;
	bool found;
	char buf[256];
	struct libusb20_device	*pdev;
	struct libusb20_config	*cfg;
	struct libusb20_backend	*pbe;
	struct LIBUSB20_DEVICE_DESC_DECODED    *ddesc;
	struct LIBUSB20_INTERFACE_DESC_DECODED *idesc;

	if (!get_ugen_bus_and_addr(ugen, &bus, &addr))
		return (-1);
	pbe = libusb20_be_alloc_default();
	for (type = -1, found = false, pdev = NULL;
	    !found && (pdev = libusb20_be_device_foreach(pbe, pdev));) {
		if (libusb20_dev_get_bus_number(pdev) != bus ||
		    libusb20_dev_get_address(pdev) != addr)
			continue;
		if (libusb20_dev_open(pdev, 0))
			err(EXIT_FAILURE, "libusb20_dev_open()");
		ddesc = libusb20_dev_get_device_desc(pdev);
		for (i = 0; i !=  ddesc->bNumConfigurations && !found; i++) {
			cfg = libusb20_dev_alloc_config(pdev, i);
			if (cfg == NULL)
				continue;
			for (j = 0; j != cfg->num_interface && !found; j++) {
				idesc = &(cfg->interface[j].desc);
				if (idesc->bInterfaceClass == USB_CLASS_UMASS) {
					switch (idesc->bInterfaceSubClass) {
					case USB_SUBCLASS_UMASS:
						type = ST_USBDISK;
						found = true;
						break;
					case USB_SUBCLASS_MMC:
						type = ST_USB_CARDREADER;
						found = true;
						break;
					}
				} else if (idesc->bInterfaceClass ==
				    USB_CLASS_PTP &&
					idesc->bInterfaceSubClass ==
				    USB_SUBCLASS_PTP &&
					idesc->bInterfaceProtocol ==
				    USB_PROTOCOL_PTP) {
					type = ST_PTP;
					found = true;
				} else if (libusb20_dev_req_string_simple_sync(
				    pdev, idesc->iInterface, buf,
				    sizeof(buf)) != 0)
					continue;
				else if (strcmp(buf, "MTP") == 0) {
					found = true;
					type = ST_MTP;
				}
			}
			free(cfg);
		}
		if (libusb20_dev_close(pdev))
                        err(EXIT_FAILURE, "libusb20_dev_close()");
	}
	libusb20_be_free(pbe);

	return (type);
}

static char *
get_lvm_dev(const char *path)
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
 * Unmounts a CD/DVD and ejects it. If 'force' is true, unmounting
 * the media, even if it's busy, will be enforced.
 */
static int
eject_media(client_t *cli, sdev_t *devp, bool force)
{
	int	  i, error;
	char	  *disk;
	union ccb *ccb;
	struct cam_device *cd;

	if (!devp->ejectable) {
		cliprint(cli, "E:command=eject:code=%d", ERR_NOT_EJECTABLE);
		return (ERR_NOT_EJECTABLE);
	}
	if ((devp->mounted && devp->cmd_mounted) || getmntpt(devp) != NULL) {
		if ((error = unmount_device(cli, devp, force, true)) != 0) {
			cliprint(cli, "E:command=eject:code=%d", error);
			return (error);
		}
	}
	if (devp->iface->type == IF_TYPE_LVM)
		disk = get_diskname(devp->realdev);
	else
		disk = get_diskname(devp->dev);
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
			(void)has_media(devp->dev);
			break;
		} else
			error = -1;
	}
	cam_close_device(cd);
	cam_freeccb(ccb);
	if (error != 0) {
		cliprint(cli, "E:command=eject:code=%d", error);
		if (error > (1 << 8))
			logprint("Ejecting %s by UID %d failed", devp->dev,
			    cli->uid);
		else
			logprintx("Ejecting %s by UID %d failed", devp->dev,
			    cli->uid);
	} else {
		cliprint(cli, "O:command=eject");
		/*
		 * Some USB sticks seem to be ejected, but do not disappear
		 * from devfs. Just to make sure that clients can't send
		 * further commands to the device, we let it vanish.
		 */
		if (devp->st != NULL && devp->st->type == ST_USBDISK)
			del_device(devp);
		else if (devp->iface->type == IF_TYPE_CD) {
			/*
			 * In case of CD/DVD notify the client immediately,
			 * instead of waiting for the next do_poll().
			 */
			devp->visible	= false;
			devp->has_media = false;
			notifybc(devp, false);
		}
	}
	return (error);
}

static int
set_cdrspeed(client_t *cli, sdev_t *devp, int speed)
{
	int fd, error;

	if (speed > CDR_MAX_SPEED || speed <= 0) {
		cliprint(cli, "E:command=speed:code=%d", ERR_INVALID_ARGUMENT);
		return (ERR_INVALID_ARGUMENT);
	}
	speed *= 177;
	
	if ((fd = open(devp->dev, O_RDWR)) == -1) {
		cliprint(cli, "E:command=speed:code=%d", errno);
		logprint("open(%s)", devp->dev);
		return (errno);
	}
	if (ioctl(fd, CDRIOCREADSPEED, &speed) == -1) {
		error = errno;
		logprint("ioctl(%s, CDRIOCREADSPEED, %d)", devp->dev,
		    speed / 177);
		cliprint(cli, "E:command=speed:code=%d", errno);
	} else {
		error = 0;
		devp->speed = speed / 177;
		cliprint(cli, "O:command=speed:speed=%d", devp->speed);
		cliprintbc(cli, "V:speed=%d:dev=%s",
		    devp->speed, devp->dev);
	}
	(void)close(fd);

	return (error);
}

static int
devd_connect()
{
	int  i, s;

	for (i = 0, s = -1; i < 30 && s == -1; i++) {
		if ((s = uconnect(PATH_DEVD_SOCKET)) == -1)
			(void)sleep(1);
	}
	return (s);
}

/* 
 * Connect to a UNIX domain socket.
 * 
 */
static int
uconnect(const char *path)
{
	int s;
	struct sockaddr_un saddr;

	if ((s = socket(PF_LOCAL, SOCK_STREAM, 0)) == -1)
		return (-1);
	(void)memset(&saddr, (unsigned char)0, sizeof(saddr));
	(void)snprintf(saddr.sun_path, sizeof(saddr.sun_path), "%s", path);
	saddr.sun_family = AF_LOCAL;
	if (connect(s, (struct sockaddr *)&saddr, sizeof(saddr)) == -1)
		return (-1);
	if (fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK) == -1)
		return (-1);
	return (s);
}

static int
send_string(int socket, const char *str)
{
	fd_set wrset;

	FD_ZERO(&wrset); FD_SET(socket, &wrset);
	while (select(socket + 1, 0, &wrset, 0, 0) == -1) {
		if (errno != EINTR) {
			logprint("select()");
			return (-1);
		}
	}
	while (write(socket, str, strlen(str)) == -1) {
		if (errno != EINTR) {
			logprint("write()");
			return (-1);
		}
	}
	return (0);
}

static void
cliprint(client_t *cli, const char *fmt, ...)
{
	int	saved_errno;
	va_list	ap;

	saved_errno = errno;
	va_start(ap, fmt);
	(void)vsnprintf(cli->msg, sizeof(cli->msg) - 2, fmt, ap);
	(void)strcat(cli->msg, "\n");
	(void)send_string(cli->s, cli->msg);
	errno = saved_errno;
}

static void
cliprintbc(client_t *exclude, const char *fmt, ...)
{
	int	i, saved_errno;
	va_list	ap;

	saved_errno = errno;
	for (i = 0; i < nclients; i++) {
		if (exclude != NULL && exclude->id == clients[i]->id)
			continue;
		va_start(ap, fmt);
		(void)vsnprintf(clients[i]->msg, sizeof(clients[i]->msg) - 2,
		    fmt, ap);
		(void)strcat(clients[i]->msg, "\n");
		(void)send_string(clients[i]->s, clients[i]->msg);
	}
	errno = saved_errno;
}

/*
 * Send a device add/remove string to a client.
 */
static void
notify(client_t *cli, sdev_t *devp, bool add)
{
	int  len;
	char buf[_POSIX2_LINE_MAX];

	if (add) {
		len = 0;
		len += snprintf(buf + len, sizeof(buf) - len, "+:dev=%s",
		    devp->dev);
		if (devp->fs != NULL) {
			len += snprintf(buf + len, sizeof(buf) - len, ":fs=%s",
			    devp->fs->name);
		}
		if (devp->name != NULL) {
			len += snprintf(buf + len, sizeof(buf) - len,
			    ":volid=%s", devp->name);
		}
		if (devp->mntpt != NULL) {
			len += snprintf(buf + len, sizeof(buf) - len,
			    ":mntpt=%s", devp->mntpt);
		}
		len += snprintf(buf + len, sizeof(buf) - len, ":type=%s",
		    devp->st->name);
		if (devp->iface->type == IF_TYPE_CD) {
			len += snprintf(buf + len, sizeof(buf) - len,
			    ":speed=%d", devp->speed);
		}
		len += snprintf(buf + len, sizeof(buf) - len, ":cmds=");
		len += snprintf(buf + len, sizeof(buf) - len, "%s%s",
		    devp->fs != NULL ? "mount,unmount" : "",
		    devp->ejectable ? "," : "");
		len += snprintf(buf + len, sizeof(buf) - len, "%s%s",
		    devp->ejectable ? "eject" : "",
		    devp->iface->type == IF_TYPE_CD ? ",speed" : "");
		cliprint(cli, "%s", buf);
	} else
		cliprint(cli, "-:dev=%s", devp->dev);
}

/*
 * Send a device add/remove string to all clients.
 */
static void
notifybc(sdev_t *devp, bool add)
{
	int i;

	for (i = 0; i < nclients; i++)
		notify(clients[i], devp, add);
}

/*
 * Reads lines from the client's socket, parses them and
 * takes actions accordingly.
 */
static int
serve_client(client_t *cli)
{
	int n, error;
	/*
	 * Read a line from socket. If the line is longer than
	 * sizeof(buf), or if it contains unprintable bytes, read
	 * until end of line, and send the client an error message.
	 */
	do {
		if ((n = client_readln(cli, &error)) > 0)
			exec_cmd(cli, cli->buf);
	} while (n > 0 && has_line(cli));

	if (n == 0)
		return (0);
	if (error == SOCK_ERR_IO_ERROR)
		logprint("client_readln() error. Closing client connection");
	/* Client disconnected or error. */
	del_client(cli);

	return (-1);
}

static void
exec_cmd(client_t *cli, char *cmdstr)
{
	int  argc, i;
	char *p, *last, *argv[12];
	struct command_s *cp;

	if (strlen(cmdstr) == 0) {
		/* Ignore empty strings */
		return;
	}
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
	sdev_t *devp;

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
	if ((devp = lookup_dev(argv[i])) == NULL || !devp->visible) {
		cliprint(cli, "E:command=eject:code=%d", ERR_NO_SUCH_DEVICE);
		return;
	}
	(void)eject_media(cli, devp, force);
}

static void
cmd_size(client_t *cli, char **argv)
{
	int	      n, fd;
	sdev_t	      *devp;
	struct statfs s;

	if (argv[0] == NULL) {
		cliprint(cli, "E:command=size:code=%d", ERR_SYNTAX_ERROR);
		return;
	}
	if ((devp = lookup_dev(argv[0])) == NULL || !devp->visible) {
		cliprint(cli, "E:command=size:code=%d", ERR_NO_SUCH_DEVICE);
		return;
	}
	if (devp->mntpt != NULL) {
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
			if (statfs(devp->mntpt, &s) == -1) {
				cliprint(cli, "E:command=size:code=%d", errno);
				return;
			}
		} while (n++ < 3 && s.f_blocks <= 1);

		cliprint(cli,
		    "O:command=size:dev=%s:mediasize=%llu:free=%llu:used=%llu",
		    devp->dev,
		    (uint64_t)(s.f_blocks * s.f_bsize),
		    (uint64_t)(s.f_bsize  * s.f_bfree),
		    (uint64_t)(s.f_bsize  * (s.f_blocks - s.f_bfree)));
	} else {
		if (devp->st != NULL && (devp->st->type == ST_MTP ||
		    devp->st->type == ST_PTP)) {
			cliprint(cli,
			    "O:command=size:dev=%s:mediasize=0:free=0:used=0",
			    devp->dev);
			return;
		}
		if ((fd = open(devp->dev, O_RDONLY | O_NONBLOCK)) == -1) {
			cliprint(cli, "E:command=size:code=%d", errno);
			return;
		}
		cliprint(cli,
		    "O:command=size:dev=%s:mediasize=%llu:free=0:used=0",
		    devp->dev, (uint64_t)g_mediasize(fd));
		(void)close(fd);
	}
}

static void
cmd_speed(client_t *cli, char **argv)
{
	int	speed;
	sdev_t *devp;

	if (argv[0] == NULL || argv[1] == NULL) {
		cliprint(cli, "E:command=speed:code=%d", ERR_SYNTAX_ERROR);
		return;
	}
	if ((devp = lookup_dev(argv[0])) == NULL || !devp->visible) {
		cliprint(cli, "E:command=speed:code=%d", ERR_NO_SUCH_DEVICE);
		return;
	}
	speed = strtol(argv[1], NULL, 10);
	(void)set_cdrspeed(cli, devp, speed);
}

static void
cmd_mount(client_t *cli, char **argv)
{
	sdev_t *devp;

	if (argv[0] == NULL) {
		cliprint(cli, "E:command=mount:code=%d", ERR_SYNTAX_ERROR);
		return;
	}
	if ((devp = lookup_dev(argv[0])) == NULL || !devp->visible) {
		cliprint(cli, "E:command=mount:code=%d", ERR_NO_SUCH_DEVICE);
		return;
	}
	(void)mount_device(cli, devp);
}

static void
cmd_unmount(client_t *cli, char **argv)
{
	int	i;
	bool	force;
	sdev_t *devp;

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
	if ((devp = lookup_dev(argv[i])) == NULL || !devp->visible) {
		cliprint(cli, "E:command=unmount:code=%d", ERR_NO_SUCH_DEVICE);
		return;
	}
	(void)unmount_device(cli, devp, force, false);
}

static void
cmd_quit(client_t *cli, char **argv)
{
	del_client(cli);
}

static time_t
poll_mntbl()
{
	int n;
	static size_t bufsz = 0;
	static struct statfs *buf;

	if (bufsz == 0) {
		/* Init */
		while ((n = getfsstat(NULL, 0, MNT_WAIT)) == -1)
			(void)usleep(500000);
		bufsz = (n + 8) * sizeof(struct statfs);
		if ((buf = malloc(bufsz)) == NULL)
			err(EXIT_FAILURE, "malloc()");
	}
	if ((n = getfsstat(buf, bufsz, MNT_WAIT)) != -1) {
		while (n > 0 && n * sizeof(struct statfs) >= bufsz) {
			bufsz += 8 * sizeof(struct statfs);
			if ((buf = realloc(buf, bufsz)) == NULL)
				err(EXIT_FAILURE, "realloc()");
			if ((n = getfsstat(buf, bufsz, MNT_WAIT)) == -1)
				logprint("getfsstat()");
		}
	} else
		logprint("getfsstat()");
	if (n > 0) {
		check_mntbl(buf, n);
		check_fuse_mount(buf, n);
		check_fuse_unmount(buf, n);
	}

	return (time(NULL));
}

static void
check_fuse_mount(struct statfs *sb, int nsb)
{
	int	   i, j;
	bool	   found;
	sdev_t	   *devp;
	const char *q;

	for (i = 0; i < nsb; i++) {
		q = devbasename(sb[i].f_mntfromname);
		/* Check for new FUSE device mounts */
		if (strncmp(q, "fuse", 4) == 0) {
			for (found = false, j = 0; j < ndevs && !found; j++) {
				devp = devs[j];
				if (devp->mntpt == NULL)
					continue;
				if (strcmp(devp->mntpt, sb[i].f_mntonname) == 0)
					found = true;
			}
			if (!found) {
				/* New FUSE device mounted. */
				add_fuse_device(sb[i].f_mntonname);
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

	for (i = 0; i < ndevs; i++) {
		if (devs[i]->st == NULL)
			continue;
		if (devs[i]->iface->type != IF_TYPE_FUSE)
			continue;
		for (j = 0, found = false; !found && j < nsb; j++) {
			if (strcmp(devs[i]->mntpt, sb[j].f_mntonname) == 0)
				found = true;
		}
		if (!found)
			del_device(devs[i]);
	}
}

static bool
match_glabel(sdev_t *devp, const char *dev)
{
	int   i;
	char *p;

	dev = devbasename(dev);
	for (i = 0; i < NGLBLPRFX && devp->glabel[i] != NULL; i++) {
		/* Skip the glabel-prefix (ufs/, cd9660/, etc.). */
		if ((p = strchr(devp->glabel[i], '/')) != NULL)
			p++;
		else
			p = devp->glabel[i];
		if (strcmp(devp->glabel[i], dev) == 0 || strcmp(p, dev) == 0)
			return (true);
	}

	return (false);
}

static void
check_mntbl(struct statfs *sb, int nsb)
{
	int	   i, j;
	bool	   found;
	sdev_t	   *devp;
	const char *q, *mntpt;

	for (i = 0; i < ndevs; i++) {
		if (devs[i]->st == NULL)
			continue;
		if (devs[i]->iface->type == IF_TYPE_FUSE)
			continue;
		devp = devs[i];
		for (j = 0, found = false; !found && j < nsb; j++) {
			q = devbasename(sb[j].f_mntfromname);
			if (strcmp(devbasename(devp->dev), q) != 0) {
				/*
				 * Check if the device was mounted using its
				 * glabel.
				 */
				found = match_glabel(devp, q);
			} else
				found = true;
			if (found)
				mntpt = sb[j].f_mntonname;
		}
		if (found) {
			if (!devp->mounted || devp->mntpt == NULL) {
				/* Mounted. */
				devp->mntpt = strdup(mntpt);
				if (devp->mntpt == NULL)
					err(EXIT_FAILURE, "strdup()");
				devp->mounted = true;
				cliprintbc(NULL, "M:dev=%s:mntpt=%s",
				    devp->dev, devp->mntpt);
			} else if (devp->mounted &&
			    strcmp(devp->mntpt, mntpt) != 0) {
				/* Remounted */
				rmntpt(devp->mntpt);
				cliprintbc(NULL, "U:dev=%s:mntpt=%s",
				    devp->dev, devp->mntpt);
				free(devp->mntpt);
				devp->mntpt = strdup(mntpt);
				if (devp->mntpt == NULL)
					err(EXIT_FAILURE, "strdup()");
				cliprintbc(NULL, "M:dev=%s:mntpt=%s",
				    devp->dev, devp->mntpt);
			}
		} else if (devp->mounted) {
			if (devp->cmd_mounted) {
				if (is_mntpt(devp->mntpt))
					continue;
			}	
			/* Unmounted */
			rmntpt(devp->mntpt);
			cliprintbc(NULL, "U:dev=%s:mntpt=%s",
			    devp->dev, devp->mntpt);
			/* Restore ownership in case we changed it. */
			(void)change_owner(devp, devp->owner);
			free(devp->mntpt);
			devp->mntpt   = NULL;
			devp->mounted = false;
		}
	}
}

