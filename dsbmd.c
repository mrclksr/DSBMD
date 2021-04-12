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
#include <assert.h>
#include <sys/types.h>
#include <camlib.h>
#include <cam/cam_ccb.h>
#include <cam/scsi/scsi_message.h>
#include <cam/scsi/scsi_pass.h>
#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <fstab.h>
#include <grp.h>
#include <isofs/cd9660/iso.h>
#include <libgeom.h>
#include <libusb20_desc.h>
#include <libusb20.h>
#include <libutil.h>
#include <limits.h>
#include <locale.h>
#include <login_cap.h>
#include <paths.h>
#include <pthread.h>
#include <pwd.h>
#include <setjmp.h>
#include <regex.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdio.h>
#include <sys/cdrio.h>
#include <sys/disk.h>
#include <sys/disklabel.h>
#include <sys/iconv.h>
#include <sys/linker.h>
#include <sys/mdioctl.h>
#include <sys/module.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <vm/vm_param.h>

#include "common.h"
#include "fs.h"
#include "dsbmd.h"
#include "dsbcfg/dsbcfg.h"
#include "config.h"

#define MNTPTMODE	   (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
#define MNTDIRPERM	   (S_IRWXU | S_IXGRP | S_IRGRP | S_IXOTH | S_IROTH)
#define NCOMMANDS	   (sizeof(commands) / sizeof(struct command_s))

#define USB_SUBCLASS_PTP   0x01
#define USB_SUBCLASS_MMC   0x02
#define USB_SUBCLASS_SFF   0x05
#define USB_SUBCLASS_UMASS 0x06
#define USB_CLASS_PTP	   0x06
#define USB_CLASS_UMASS	   0x08
#define USB_PROTOCOL_PTP   0x01

#define SCSI_SENSE_NOT_PRESENT	  "02 3a"
#define SCSI_SENSE_BECOMING_READY "02 04 01"
#define SCSI_SENSE_MEDIA_CHANGE	  "06 28 00"

#define die(msg, ...) do { \
	logprint(msg, ##__VA_ARGS__); exit(EXIT_FAILURE); \
} while (0)

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
static int	eject_media(client_t *, sdev_t *, bool);
static int	set_cdrspeed(client_t *, sdev_t *, int);
static int	set_msdosfs_locale(const char *, struct iovec**, size_t *);
static int	uconnect(const char *);
static int	devd_connect(void);
static int	attach_mddev(client_t *, const char *);
static int	detach_mddev(sdev_t *);
static int	send_string(int, const char *);
static int	client_readln(client_t *, int *);
static int	serve_client(client_t *);
static int	strtoargv(char *, char **, size_t, size_t *);
static bool	match_part_dev(const char *, size_t);
static bool	match_glabel(sdev_t *, const char *);
static bool	has_media(const char *);
static bool	scsi_has_media(const char *);
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
static void	*poll_thr(void *);
static void	*devd_thr(void *);
static void	*cmd_thr(void *);
static void	lockpidfile(void);
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
static void	cmd_mdattach(client_t *, char **);
static void	cmd_quit(client_t *cli, char **);
static void	notifybc(sdev_t *, bool);
static void	notify(client_t *, sdev_t *, bool);
static void	cliprint(client_t *, const char *, ...);
static void	cliprintbc(client_t *, const char *, ...);
static void	check_mntbl(struct statfs *, int);
static void	check_fuse_mount(struct statfs *, int);
static void	check_fuse_unmount(struct statfs *, int);
static void	add_errbuf(struct iovec **, size_t *, char **, size_t);
static void	extend_iovec(struct iovec **, size_t *, const char *,
		    const char *);
static time_t	poll_mntbl(void);
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
	char *system;	  /* Bus or DEVFS */
	char *subsystem;  /* Only CDEV is interesting to us. */
	char *type;	  /* Event type: CREATE, DESTROY. */
	char *cdev;	  /* Device name. */
	char *device;	  /* Device name (system == CAM) */
	char *scsi_sense; /* SCSI sense data */
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
	{ "HDD",	ST_FUSE	     },
	{ "BLURAY",	ST_BLURAY    }
};

const iface_t interfaces[] = {
	{ RE_CD,	IF_TYPE_CD   },
	{ RE_ADA,	IF_TYPE_ADA  },
	{ RE_DA,	IF_TYPE_DA   },
	{ RE_UGEN,	IF_TYPE_UGEN },
	{ RE_LVM,	IF_TYPE_LVM  },
	{ RE_MMC,	IF_TYPE_MMC  },
	{ RE_MD,	IF_TYPE_MD   },
	{ RE_FUSE,	IF_TYPE_FUSE },
	{ RE_NVD,	IF_TYPE_NVD  }
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
	{ "size",	&cmd_size    },
	{ "mdattach",	&cmd_mdattach}
};

typedef struct cmdthread_s {
	char		**argv;
	bool		timedout;
	jmp_buf		jmpenv;
	client_t	*cli;
	pthread_t	tid;
	pthread_cond_t	cond;
	pthread_mutex_t	mtx;
	struct command_s *cmd;
} cmdthread_t;

struct thrlist_s {
	cmdthread_t *cmdthr;
	SLIST_ENTRY(thrlist_s) next;
};

/* 
 * Struct to represent a message sent from the threads
 * to the main thread.
 */
struct ipcmsg_s {
	char	dev[MNAMELEN];
	sdev_t	*devp;
	uint8_t	type;
};

enum {
	MSGTYPE_ADD_DEVICE = 1, MSGTYPE_UPDATE_DEVICE, MSGTYPE_DEL_DEVICE,
	MSGTYPE_CHECK_FOR_MEDIA, MSGTYPE_MEDIA_REMOVED
};

static int	ipcsv[2];		/* IPC socket pair for threads. */
static uid_t	*allow_uids   = NULL;	/* UIDs allowed to connect. */
static gid_t	*allow_gids   = NULL;	/* GIDs allowed to connect. */
static dsbcfg_t	*cfg	      = NULL;
static struct pidfh *pfh      = NULL;	/* PID file handle. */
static pthread_mutex_t pollqmtx;
static pthread_mutex_t ipcsockmtx;
static SLIST_HEAD(, devlist_s) devs;	/* List of mountable devs. */
static SLIST_HEAD(, clilist_s) clis;	/* List of connected clients. */
static SLIST_HEAD(, devlist_s) pollq;	/* Poll queue */
static SLIST_HEAD(, thrlist_s) cmdthreads;

int
main(int argc, char *argv[])
{
	int	       i, sflags, maxfd, ch, lsock;
	int	       csock, mntchkiv;
	DIR	       *dirp, *dirp2;
	bool	       fflag;
	FILE	       *fp;
	char	       lvmpath[512], **v;
	time_t	       mntchktime;
	sdev_t	       *devp;
	fd_set	       allset, rset;
	sigset_t       sset;
	client_t       *cli;
	pthread_t      tid;
	struct stat    sb;
	struct group   *gr;
	struct passwd  *pw;
	struct dirent  *dp, *dp2;
	struct timeval tv;
	struct ipcmsg_s msg;
	struct sockaddr_un s_addr;
	struct clilist_s *ep, *ep_tmp;

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
	assert(CFG_NVARS == nvardefs);

	cfg = dsbcfg_read(NULL, PATH_CONFIG, vardefs, CFG_NVARS);
	if (cfg == NULL)
		errx(EXIT_FAILURE, "%s", dsbcfg_strerror());
	check_cfg_version(cfg);
	check_cfg_opts(cfg);

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
	/* Timeout for select() */
	mntchkiv = dsbcfg_getval(cfg, CFG_MNTCHK_INTERVAL).integer;
	if (mntchkiv <= 0) {
		logprintx("%s <= 0. Assuming %s = 1",
		    dsbcfg_varname(cfg, CFG_MNTCHK_INTERVAL),
		    dsbcfg_varname(cfg, CFG_MNTCHK_INTERVAL));
		mntchkiv = 1;
	}
	for (i = 0; i < nfstypes; i++) {
		switch (fstype[i].id) {
		case UFS:
			INITFS(i, UFS);
			break;
		case HFSP:
			INITFS(i, HFSP);
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
		case XFS:
			INITFS(i, XFS);
			break;
		case BTRFS:
			INITFS(i, BTRFS);
			break;
		default:
			/* Just to soothe clang. */
			break;
		}
	}
	SLIST_INIT(&devs);
	SLIST_INIT(&clis);
	SLIST_INIT(&pollq);

	/* Ready to deamonize. */
	if (!fflag) {
		if (daemon(0, 0) == -1)
			err(EXIT_FAILURE, "Failed to daemonize");
		lockpidfile();
		/* Redirect error messages, stdout and stderr to logfile. */
		if ((fp = fopen(PATH_DSBMD_LOG, "a+")) == NULL)
			err(EXIT_FAILURE, "fopen()");
		(void)setvbuf(fp, NULL, _IOLBF, 0);
		(void)dup2(fileno(fp), STDERR_FILENO);
		(void)dup2(fileno(fp), STDOUT_FILENO);
		err_set_file(fp);
	} else
		lockpidfile();
	sigfillset(&sset);
	sigdelset(&sset, SIGINT);
	sigdelset(&sset, SIGTERM);
	sigdelset(&sset, SIGQUIT);
	sigdelset(&sset, SIGHUP);
	if (sigprocmask(SIG_SETMASK, &sset, NULL) == -1)
		die("sigprocmask()");
	(void)signal(SIGINT, cleanup);
	(void)signal(SIGTERM, cleanup);
	(void)signal(SIGQUIT, cleanup);
	(void)signal(SIGHUP, cleanup);

	logprintx("%s started", PROGRAM);

	/* Open the listening socket for the clients. */
        (void)unlink(PATH_DSBMD_SOCKET);
	if ((lsock = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1)
		die("socket()");
	(void)memset((char *)&s_addr, 0, sizeof(s_addr));
	(void)memcpy(s_addr.sun_path, PATH_DSBMD_SOCKET,
	    strlen(PATH_DSBMD_SOCKET));
	s_addr.sun_family = AF_LOCAL;
	if (bind(lsock, (struct sockaddr *)&s_addr, sizeof(s_addr)) == -1)
		die("bind()");
	if (chmod(PATH_DSBMD_SOCKET, SOCKET_MODE) == -1)
		die("chmod(%s)", PATH_DSBMD_SOCKET);
	if (listen(lsock, dsbcfg_getval(cfg, CFG_MAX_CLIENTS).integer) == -1)
		die("listen()");
	/*
	 * Make the listening socket non blocking in order to protect the
	 * server from certain DoS attacks.
	 */
	if ((sflags = fcntl(lsock, F_GETFL)) == -1)
		die("fcntl()");
	sflags |= O_NONBLOCK;
	if (fcntl(lsock, F_SETFL, sflags) == -1)
		die("fcntl()");
	/* Get all currently installed disks. */
	if (chdir(_PATH_DEV) == -1)
		die("chdir(%s)", _PATH_DEV);
	if ((dirp = opendir(".")) == NULL)
		die("opendir(%s)", _PATH_DEV);
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
		die("chdir(/)");
	if (socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, ipcsv) == -1)
		die("socketpair()");
	maxfd = lsock > ipcsv[0] ? lsock : ipcsv[0];

	FD_ZERO(&allset);
	FD_SET(lsock, &allset); FD_SET(ipcsv[0], &allset);

	(void)pthread_mutex_init(&ipcsockmtx, NULL);
	(void)pthread_mutex_init(&pollqmtx, NULL);

	if (pthread_create(&tid, NULL, devd_thr, &ipcsv[1]) != 0)
		die("pthread_create()");
	/* Main loop. */
	for (mntchktime = 0;;) {
		rset = allset;
		tv.tv_sec = mntchkiv; tv.tv_usec = 0;
		if (time(NULL) - mntchktime >= mntchkiv) 
			mntchktime = poll_mntbl();
		switch (select(maxfd + 1, &rset, NULL, NULL, &tv)) {
		case -1:
			if (errno == EINTR)
				continue;
			die("select()");
			/* NOTREACHED */
		case 0:
			mntchktime = poll_mntbl();
			continue;
		}
		if (FD_ISSET(lsock, &rset)) {
			/* A client has connected. */
			if ((cli = process_connreq(lsock)) != NULL) {
				maxfd = maxfd > cli->s ? maxfd : cli->s;
				FD_SET(cli->s, &allset);
			}
		}
		if (FD_ISSET(ipcsv[0], &rset)) {
			/* Polled device changed. */
			if (recv(ipcsv[0], &msg, sizeof(msg),
			    MSG_WAITALL) == -1) {
				if (errno == EINTR)
					continue;
				die("recv()");
			}
			switch (msg.type) {
			case MSGTYPE_ADD_DEVICE:
				add_device(msg.dev);
				break;
			case MSGTYPE_DEL_DEVICE:
				if ((devp = lookup_dev(msg.dev)) == NULL)
					break;
				del_device(devp);
				break;
			case MSGTYPE_UPDATE_DEVICE:
				update_device(msg.devp);
				break;
			case MSGTYPE_CHECK_FOR_MEDIA:
				add_to_pollqueue(msg.devp);
				break;
			case MSGTYPE_MEDIA_REMOVED:
				msg.devp->has_media = false;
				update_device(msg.devp);
			}
		}
		SLIST_FOREACH_SAFE(ep, &clis, next, ep_tmp) {
			if (!FD_ISSET(ep->cli->s, &rset))
				continue;
			csock = ep->cli->s;
			if (serve_client(ep->cli) == -1 || ep->cli->s == -1) {
				/* Disconnected */
				FD_CLR(csock, &allset);
				(void)close(csock);
				del_client(ep->cli);
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
	bool force, unmount_on_exit;
	const char *val = dsbcfg_getval(cfg, CFG_UNMOUNT_ON_EXIT).string;
	struct devlist_s *ep;

	unmount_on_exit = force = false;
	if (strcmp(val, "yes") == 0)
		unmount_on_exit = true;
	else if (strcmp(val, "force") == 0)
		unmount_on_exit = force = true;
	SLIST_FOREACH(ep, &devs, next) {
		if (!ep->devp->mounted || !unmount_on_exit ||
		    !ep->devp->dsbmd_mounted)
			continue;
		logprintx("Unmounting %s", ep->devp->mntpt);
		(void)unmount(ep->devp->mntpt, force ? MNT_FORCE : 0);
	}
	cliprintbc(NULL, "S");
	logprintx("%s exited", PROGRAM);
	pidfile_remove(pfh);
	exit(EXIT_SUCCESS);
}

static void
lockpidfile()
{

	/* Check if deamon is already running. */
	if ((pfh = pidfile_open(PATH_PID_FILE, 0600, NULL)) == NULL) {
		if (errno == EEXIST)
			errx(EXIT_FAILURE, "%s is already running.", PROGRAM);
		err(EXIT_FAILURE, "Failed to create PID file.");
	}
	pidfile_write(pfh);
}

static sdev_t *
lookup_dev(const char *dev)
{
	sdev_t *devp;
	struct devlist_s *ep;

	dev = devbasename(dev);

	SLIST_FOREACH(ep, &devs, next) {
		devp = ep->devp;
		if (strcmp(dev, devbasename(devp->dev)) == 0)
			return (devp);
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
	client_t      *cp;
	static int    id = 1;
	struct group  *grp;
	struct passwd *pw;
	struct devlist_s *ep;
	struct clilist_s *cep;

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
	if ((cp = malloc(sizeof(client_t))) == NULL ||
	    (cep = malloc(sizeof(struct clilist_s))) == NULL)
		die("malloc()");
	cep->cli = cp;
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
	SLIST_FOREACH(ep, &devs, next) {
		if (ep->devp->visible)
			notify(cp, ep->devp, true);
	}
	/* Terminate device list output. */
	cliprint(cp, "=");
	SLIST_INSERT_HEAD(&clis, cep, next);
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
	struct clilist_s *ep;

	SLIST_FOREACH(ep, &clis, next) {
		if (cli == ep->cli)
			break;
	}
	if (ep == NULL)
		return;
	logprintx("Client with UID %d disconnected", cli->uid);
	if (cli->s > -1)
		(void)close(cli->s);
	free(cli->gids);
	free(cli);
	SLIST_REMOVE(&clis, ep, clilist_s, next);

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
	char   c;
	bool   badchar;
	size_t len, bufsz = sizeof(cli->buf) - 1;

	*error = 0;
	for (;;) {
 		if ((n = read(cli->s, &c, 1)) == -1) {
			if (errno == EINTR) {
				continue;
			} else if (errno == EAGAIN) {
				/* No more bytes available. */
				return (0);
			} else {
				*error = SOCK_ERR_IO_ERROR;
				return (-1);
			}
		} else if (n == 0) {
			*error = SOCK_ERR_CONN_CLOSED;
			return (-1);
		}
		if (c == '\n')
			break;
		if (cli->overflow)
			return (0);
		cli->buf[cli->rd++] = (char)c;
		if (cli->rd == bufsz) {
			cli->overflow = true;
			cli->rd = 0;
		}
	}
	/* c == '\n' */
	if (!cli->overflow)
		cli->buf[cli->rd] = '\0';
	len = cli->rd; cli->rd = 0;

	if (cli->overflow) {
		cli->overflow = false;
		cliprint(cli, "E:code=%d\n", ERR_STRING_TOO_LONG);
	} else {
		badchar = false;
		for (i = 0; i < len; i++) {
			if (!isprint(cli->buf[i]))
				badchar = true;
		}
		if (badchar)
			cliprint(cli, "E:code=%d\n", ERR_BAD_STRING);
		else
			return (1);
	}
	return (0);
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
			die("accept()");
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
	int	      n, rd;
	static int    bufsz = 0;
	static char   seq[1024], *lnbuf = NULL;
	struct iovec  iov;
	struct msghdr msg;
	
	if (lnbuf == NULL) {
		if ((lnbuf = malloc(_POSIX2_LINE_MAX)) == NULL)
			return (NULL);
		bufsz = _POSIX2_LINE_MAX;
	}
	iov.iov_len  = sizeof(seq);
	iov.iov_base = seq;
	msg.msg_iov  = &iov;
	msg.msg_iovlen = 1;

	for (n = rd = *error = 0;;) {
		msg.msg_name    = msg.msg_control = NULL;
		msg.msg_namelen = msg.msg_controllen = 0;

		if ((n = recvmsg(s, &msg, 0)) == (ssize_t)-1) {
			if (errno == EINTR)
				continue;
			if (errno == ECONNRESET || errno == ENOTCONN) {
				*error = SOCK_ERR_CONN_CLOSED;
				return (NULL);
			}
			if (errno == EAGAIN)
				return (NULL);
			die("recvmsg()");
		} else if (n == 0 && rd == 0) {
			*error = SOCK_ERR_CONN_CLOSED;
			return (NULL);
		}
		if (rd + n + 1 > bufsz) {
			if ((lnbuf = realloc(lnbuf, rd + n + 65)) == NULL)
				die("realloc()");
			bufsz = rd + n + 65;
		}
		(void)memcpy(lnbuf + rd, seq, n);
		rd += n; lnbuf[rd] = '\0';
		if (msg.msg_flags & MSG_TRUNC) {
			logprint("recvmsg(): Message truncated");
			return (rd > 0 ? lnbuf : NULL);
		} else if (msg.msg_flags & MSG_EOR)
			return (lnbuf);
	}
	return (NULL);
}


static void
parse_devd_event(char *str)
{
	char	   *next, *var, *val, *p;
	const char *cs;

	devdevent.system = devdevent.subsystem = devdevent.type = "";
	devdevent.scsi_sense = devdevent.device = devdevent.cdev = "";

	while (*str != '\0' && (val = strchr(str, '=')) != NULL) {
		while (isspace(*str))
			str++;
		*val++ = '\0'; var = str;
		if (*val == '"') {
			++val;
			cs = "\"";
		} else
			cs = " \t\n";
		next = val + strcspn(val, cs);
		if (*next != '\0')
			*next++ = '\0';
		str = next;
		if (strcmp(var, "system") == 0)
			devdevent.system = val;
		else if (strcmp(var, "subsystem") == 0)
			devdevent.subsystem = val;
		else if (strcmp(var, "type") == 0)
			devdevent.type = val;
		else if (strcmp(var, "cdev") == 0)
			devdevent.cdev = val;
		else if (strcmp(var, "device") == 0)
			devdevent.device = val;
		else if (strcmp(var, "scsi_sense") == 0) {
			/* Skip SCSI return code. */
			if ((p = strchr(val, ' ')) != NULL)
				devdevent.scsi_sense = ++p;
			else {
				logprintx("Invalid SCSI sense data?: %s", val);
				devdevent.scsi_sense = val;
			}
		}
	}
}

static void *
poll_thr(void *socket)
{
	int	s;
	sdev_t *devp;
	struct ipcmsg_s msg;

 	s = *(int *)socket;
	for (;; sleep(3)) {
		(void)pthread_mutex_lock(&pollqmtx);
		if (SLIST_EMPTY(&pollq)) {
			/* Queue empty. Terminate thread */
			(void)pthread_mutex_unlock(&pollqmtx);
			pthread_exit(NULL);
		}
		while ((devp = media_changed()) != NULL) {
			msg.type = MSGTYPE_UPDATE_DEVICE;
			msg.devp = devp;
			(void)pthread_mutex_lock(&ipcsockmtx);
			(void)send(s, &msg, sizeof(msg), MSG_EOR);
			(void)pthread_mutex_unlock(&ipcsockmtx);
		}
		(void)pthread_mutex_unlock(&pollqmtx);
	}
	return (NULL);
}

static void *
devd_thr(void *ipcsock)
{
	int    ipc, devd, error;
	char   *ev;
	sdev_t *devp;
	fd_set rset, _rset;
	struct ipcmsg_s msg;

	ipc = *(int *)ipcsock;

	if ((devd = devd_connect()) == -1)
		die("Couldn't connect to %s", PATH_DEVD_SOCKET);
	FD_ZERO(&_rset); FD_SET(devd, &_rset);
	for (;;) {
		rset = _rset;
		if (select(devd + 1, &rset, NULL, NULL, NULL) == -1) {
			if (errno == EINTR)
				continue;
			die("select()");
		}
		if ((ev = read_devd_event(devd, &error)) != NULL) {
			if (ev[0] != '!')
				continue;
			parse_devd_event(ev + 1);
			if (strcmp(devdevent.system, "DEVFS") == 0 &&
			    strcmp(devdevent.subsystem, "CDEV") == 0) {
				if (strcmp(devdevent.type, "CREATE") == 0)
					msg.type = MSGTYPE_ADD_DEVICE;
				else if (strcmp(devdevent.type, "DESTROY") == 0)
					msg.type = MSGTYPE_DEL_DEVICE;
				else
					continue;
				(void)strncpy(msg.dev, devdevent.cdev,
				    sizeof(msg.dev));
			} else if (strncmp(devdevent.scsi_sense,
			    SCSI_SENSE_BECOMING_READY,
			    strlen(SCSI_SENSE_BECOMING_READY)) == 0    ||
			    strcmp(devdevent.type, "MEDIACHANGE") == 0 ||
			    strncmp(devdevent.scsi_sense,
			    SCSI_SENSE_MEDIA_CHANGE,
			    strlen(SCSI_SENSE_MEDIA_CHANGE)) == 0) {
				/* Media becoming ready */
				devp = lookup_dev(!devdevent.device ? \
				    devdevent.cdev : devdevent.device);
				if (devp == NULL) {
					devp = add_device(!devdevent.device ? \
					    devdevent.cdev : devdevent.device);
				}
				if (devp != NULL && !devp->has_media) {
					msg.type = MSGTYPE_CHECK_FOR_MEDIA;
					msg.devp = devp;
				} else
					continue;
			} else if (strncmp(devdevent.scsi_sense,
			    SCSI_SENSE_NOT_PRESENT,
			    strlen(SCSI_SENSE_NOT_PRESENT)) == 0) {
				/* Media not present */
				devp = lookup_dev(devdevent.device);
				if (devp != NULL &&
				    (devp->has_media || devp->in_pollq)) {
					msg.type = MSGTYPE_MEDIA_REMOVED;
					msg.devp = devp;
				} else
					continue;
			} else
				continue;
			(void)pthread_mutex_lock(&ipcsockmtx);
			(void)send(ipc, &msg, sizeof(msg), MSG_EOR);
			(void)pthread_mutex_unlock(&ipcsockmtx);
		} else if (error == SOCK_ERR_CONN_CLOSED) {
			/* Lost connection to devd. */
			(void)close(devd);
			logprintx("Lost connection to devd. Reconnecting ...");
			if ((devd = devd_connect()) == -1)
				die("Connecting to devd failed. Giving up.");
			else if (error == SOCK_ERR_IO_ERROR)
				die("read_devd_event()");
			FD_ZERO(&_rset); FD_SET(devd, &_rset);
		}
	}
}

static void
add_to_pollqueue(sdev_t *devp)
{
	pthread_t   tid;
	const char *dev;
	struct devlist_s *ep;

	if (devp->in_pollq)
		return;
	dev = devbasename(devp->dev);
	(void)pthread_mutex_lock(&pollqmtx);
	if (match_part_dev(dev, 0)) {
		/* Do not add slices */
		(void)pthread_mutex_unlock(&pollqmtx);
		return;
	}
	if (SLIST_EMPTY(&pollq)) {
		/* Start poll thread */
		if (pthread_create(&tid, NULL, poll_thr, &ipcsv[1]) != 0)
			die("pthread_create()");
		(void)pthread_detach(tid);
	}
	if ((ep = malloc(sizeof(struct devlist_s))) == NULL)
		die("malloc()");
	ep->devp = devp;
	devp->in_pollq = true;
	SLIST_INSERT_HEAD(&pollq, ep, next);
	(void)pthread_mutex_unlock(&pollqmtx);
}

static void
del_from_pollqueue(sdev_t *devp)
{
	struct devlist_s *ep;

	if (!devp->in_pollq)
		return;
	(void)pthread_mutex_lock(&pollqmtx);
	SLIST_FOREACH(ep, &pollq, next) {
		if (devp == ep->devp)
			break;
	}
	if (ep == NULL) {
		(void)pthread_mutex_unlock(&pollqmtx);
		return;
	}
	SLIST_REMOVE(&pollq, ep, devlist_s, next);
	devp->in_pollq = false;
	(void)pthread_mutex_unlock(&pollqmtx);
}

static bool
has_media(const char *dev)
{
	int    fd;
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
	else
		media = true;
	(void)close(fd);

	return (media);
}

static bool
scsi_has_media(const char *dev)
{
	bool media;
	union ccb *ccb;
	struct cam_device *cd;

	errno = 0;
	if ((cd = cam_open_device(dev, O_RDWR)) == NULL) {
		logprint("cam_open_device(%s)", dev);
		return (false);
	}
	ccb = cam_getccb(cd);
	scsi_test_unit_ready(&ccb->csio, 0, NULL, MSG_ORDERED_Q_TAG,
	    SSD_FULL_SIZE, 5000);
	ccb->ccb_h.flags |= CAM_DEV_QFRZDIS;
	if (cam_send_ccb(cd, ccb) == -1)
		media = false;
	else if ((ccb->ccb_h.status & CAM_STATUS_MASK) == CAM_REQ_CMP)
		media = true;
	else
		media = false;
	cam_close_device(cd);
	cam_freeccb(ccb);

	return (media);
}

/*
 * Return a pointer to the next device whose media changed.
 */
static sdev_t *
media_changed()
{
	bool media;
	static struct devlist_s *ep = NULL, *tmp = NULL;

	SLIST_FOREACH_FROM_SAFE(ep, &pollq, next, tmp) {
		switch (ep->devp->iface->type) {
		case IF_TYPE_DA:
		case IF_TYPE_CD:
			media = scsi_has_media(ep->devp->dev);
			break;
		default:
			media = has_media(ep->devp->dev);
		}
		if (media) {
			if (!ep->devp->has_media) {
				/* Media was inserted */
				ep->devp->has_media = true;
				return (ep->devp);
			}
		} else if (errno == ENOENT) {
			/* Check whether device was removed */
			if (access(ep->devp->dev, F_OK) == -1)
				del_device(ep->devp);
		} else if (ep->devp->has_media) {
			/* Media was removed */
			ep->devp->has_media = false;
			return (ep->devp);
		}
	}
	return (NULL);
}

static void
update_device(sdev_t *devp)
{
	char *p;

	del_from_pollqueue(devp);

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
			case ST_BLURAY:
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
				die("strdup()");
		} else if ((devp->name = strdup(devbasename(devp->dev))) == NULL)
			die("strdup()");
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
 * with a NULL pointer.
 */
static void
extend_iovec(struct iovec **iov, size_t *iovlen, const char *name,
	const char *val)
{
	size_t	     n;
	struct iovec *v;

	n = *iovlen + 2 + 1;
	if ((v = realloc(*iov, sizeof(struct iovec) * n)) == NULL)
		die("realloc()");
	if ((v[n - 3].iov_base = strdup(name)) == NULL)
		die("strdup()");
	v[n - 3].iov_len  = strlen(name) + 1;
	if ((v[n - 2].iov_base = strdup(val)) == NULL)
		die("strdup()");
	v[n - 2].iov_len  = strlen(val) + 1;
	/* Mark end of array */
	v[n - 1].iov_base = NULL;

	*iov	= v;
	*iovlen = n - 1;
}

static void
add_errbuf(struct iovec **iov, size_t *iovlen, char **errbuf, size_t len)
{
	size_t	     n;
	struct iovec *v;

	n = *iovlen + 2 + 1;
	if ((*errbuf = malloc(len)) == NULL)
		die("malloc()");
	bzero(*errbuf, len);
	if ((v = realloc(*iov, sizeof(struct iovec) * n)) == NULL)
		die("realloc()");
	if ((v[n - 3].iov_base = strdup("errmsg")) == NULL)
		die("strdup()");
	v[n - 3].iov_len  = strlen("errmsg") + 1;
	v[n - 2].iov_base = *errbuf;
	v[n - 2].iov_len  = len;
	/* Mark end of array */
	v[n - 1].iov_base = NULL;

	*iov	= v;
	*iovlen = n - 1;
}

static void
free_iovec(struct iovec *iov)
{
	int i;

	for (i = 0; iov[i].iov_base != NULL; i++)
		free(iov[i].iov_base);
	free(iov);
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
			die("initgroups()");
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
		die("login_getpwclass()");
	if (setusercontext(lc, pw, pw->pw_uid, LOGIN_SETALL) == -1)
		die("setusercontext()");
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
		die("vfork()");
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
			die("waitpid()");
		else if (ret == pid)
			return (status == 255 ? -1 : WEXITSTATUS(status));
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
					die("waitpid()");
				else if (ret == pid)
					return (ERR_TIMEOUT);
				(void)sleep(1);
				i++;
			}
		}
		return (ERR_TIMEOUT);
	}
	if (errno != 0)
		return (-1);
	return (status == 255 ? -1 : WEXITSTATUS(status));
}

static int
set_msdosfs_locale(const char *locale, struct iovec **iov, size_t *iovlen)
{
	char *prev_locale;
	const char *cs;

	prev_locale = setlocale(LC_CTYPE, NULL);
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
	if (setlocale(LC_CTYPE, locale) == NULL)
		die("setlocale(%s)", locale);
	locale = kiconv_quirkcs(cs + 1, KICONV_VENDOR_MICSFT);
	if (kiconv_add_xlat16_cspairs(ENCODING_UNICODE, locale) != 0 &&
	    errno != EEXIST)
		die("kiconv_add_xlat16_cspairs(ENCODING_UNICODE)");
	if (kiconv_add_xlat16_cspair(locale, locale,
	    KICONV_FROM_UPPER | KICONV_LOWER) != 0) {
		logprint("kiconv_add_xlat16_cspair()");
		if (prev_locale != NULL)
			setlocale(LC_CTYPE, prev_locale);
		return (-1);
	}
	extend_iovec(iov, iovlen, "cs_win", ENCODING_UNICODE);
	extend_iovec(iov, iovlen, "cs_local", locale);
	extend_iovec(iov, iovlen, "cs_dos", locale);
	extend_iovec(iov, iovlen, "kiconv", "");
	if (prev_locale != NULL)
		setlocale(LC_CTYPE, prev_locale);
	return (0);
}


static int
mymount(const char *fs, const char *dir, const char *dev, const char *opts,
	uid_t uid, gid_t gid)
{
	int	     ret, saved_errno;
	char	     *p, *op, *q, *errmsg;
	size_t	     iovlen;
	struct iovec *iov;

	iov = NULL; iovlen = 0;
	extend_iovec(&iov, &iovlen, "fstype", fs);
	extend_iovec(&iov, &iovlen, "fspath", dir);
	extend_iovec(&iov, &iovlen, "from", dev);
	if (opts != NULL) {
		if ((op = strdup(opts)) == NULL)
			die("strdup()");
		for (p = op; (p = strtok(p, ",")) != NULL; p = NULL) {
			if ((q = strchr(p, '=')) == NULL)
				q = "";
			else
				*q++ = '\0';
			extend_iovec(&iov, &iovlen, p, q);
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
	add_errbuf(&iov, &iovlen, &errmsg, 1024);
	errno = 0;

	/* Mount as user if "usermount" and vfs.usermount is set */
	if (dsbcfg_getval(cfg, CFG_USERMOUNT).boolean && usermount_set())
		switcheids(uid, gid);
	ret = nmount(iov, iovlen, 0);
	saved_errno = errno;
	if (ret != 0 && errmsg[0] != '\0')
		logprint("nmount(): %s", errmsg);
	restoreids();
	free_iovec(iov);
	errno = saved_errno;

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
		die("chown(%s)", mntpath);
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
			die("getmntpt()");
		devp->mounted = true;
		devp->dsbmd_mounted = true;
		devp->cmd_mounted = false;
		cliprint(cli, "O:command=mount:dev=%s:mntpt=%s", devp->dev,
		    devp->mntpt);
		cliprintbc(cli, "M:dev=%s:mntpt=%s", devp->dev, devp->mntpt);
		logprintx("Device %s mounted on %s by UID %d", devp->dev,
		    devp->mntpt, cli->uid);
		return (0);
	}
	cliprint(cli, "E:command=mount:code=%d",
	    errno == 0 ? ERR_UNKNOWN_ERROR : errno);
	logprint("Mounting of %s by UID %d failed", devp->dev, cli->uid);
	(void)change_owner(devp, devp->owner);
	rmntpt(mntpath);
	free(mntpath);

	return (0);
}

static int
exec_mntcmd(client_t *cli, sdev_t *devp, char *mntpath)
{
	int	    error, unit, addr;
	bool	    chown_fuse;
	char	    num[12];
	uid_t	    uid, fuse_uid;
	gid_t	    gid, fuse_gid;
	const char *mntcmd;
	struct stat sb;

	chown_fuse = false;
	if (dsbcfg_getval(cfg, CFG_USERMOUNT).boolean && usermount_set()) {
		uid = cli->uid;
		gid = cli->gids[0];
		mntcmd = devp->fs->mntcmd_u;

		if (dsbcfg_getval(cfg, CFG_CHOWN_FUSE).boolean) {
			if (access(PATH_FUSE, F_OK) == -1) {
				if (errno != ENOENT)
					warn("access(%s)", PATH_FUSE);
			} else if (stat(PATH_FUSE, &sb) == -1) {
				warn("stat(%s)", PATH_FUSE);
			} else {
				/*
				 * Change the owner of the fuse device,
				 * temporarily.
				 */
				fuse_uid = sb.st_uid;
				fuse_gid = sb.st_gid;
				if (chown(PATH_FUSE, cli->uid, fuse_gid) == -1)
					warn("chown(%s, %u)", PATH_FUSE, cli->uid);
				else
					chown_fuse = true;
			}
		}
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
		(void)get_ugen_bus_and_addr(devbasename(devp->dev), &unit, &addr);
		(void)snprintf(num, sizeof(num), "%u", unit);
		(void)setenv(ENV_USB_UNIT, num, 1);
		(void)snprintf(num, sizeof(num), "%u", addr);
		(void)setenv(ENV_USB_ADDR, num, 1);
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
		devp->dsbmd_mounted = true;
		cliprint(cli, "O:command=mount:dev=%s:mntpt=%s", devp->dev,
		    devp->mntpt);
		cliprintbc(cli, "M:dev=%s:mntpt=%s", devp->dev, devp->mntpt);
		logprintx("Device %s mounted on %s by UID %d", devp->dev,
		    devp->mntpt, cli->uid);
	} else {
		if (error == ERR_TIMEOUT)
			cliprint(cli, "E:command=mount:code=%d", error);
		else {
			cliprint(cli, "E:command=mount:code=%d:mntcmderr=%d",
			    ERR_MNTCMD_FAILED, error);
			logprint("Command %s executed by UID %d " \
				"failed with code %d", mntcmd, cli->uid,
				errno != 0 ? errno : error);
		}
		rmntpt(mntpath);
		free(mntpath);
		(void)change_owner(devp, devp->owner);
	}
	if (chown_fuse)
		(void)chown(PATH_FUSE, fuse_uid, fuse_gid);
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
	if (devp->iface->type == IF_TYPE_FUSE)
		del_device(devp);
	else
		(void)change_owner(devp, devp->owner);
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
			die("mkdir(%s)", mntdir);
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
		die("malloc()");
	(void)sprintf(mntpath, "%s/%s", mntdir, p);

	if (stat(mntpath, &sb) == -1 && (errno != ENOENT && errno != EIO))
		die("stat(%s)", mntpath);
	else if (errno == ENOENT) {
		if (mkdir(mntpath, MNTPTMODE) == -1)
			die("mkdir(%s)", mntpath);
	} else {
		/* 
		 * File exists, or we can't access the mount point due to an
		 * I/O error.  If  the  file  isn't  a  directory, or a
		 * directory  which  is  not  empty,  or  if there is any
		 * other reason why we can't delete the directory, try to
		 * create an alternative mount point.
		 */		
		if (!S_ISDIR(sb.st_mode) || rmdir(mntpath) == -1) {
			free(mntpath);
			if ((mntpath = malloc(MNAMELEN)) == NULL)
				die("malloc()");
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
						die("mkdir(%s)", mntpath);
				} else
					return (mntpath);
			}
			/*
			 * No luck so far. Create a random mount point
			 */
			(void)snprintf(mntpath, MNAMELEN, "%s/%s.XXXX",
			    mntdir, devbasename(devp->dev));
			if (mkdtemp(mntpath) == NULL)
				die("mkdtemp(%s)", mntpath);
		} else {
			/* Recreate directory */
			if (mkdir(mntpath, MNTPTMODE) == -1)
				die("mkdir(%s)", mntpath);
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
	if ((n = getmntinfo(&mb, MNT_NOWAIT)) == -1)
		die("getmntinfo()");
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
				die("strdup()");
			return (devp->mntpt);
		}
		/* Check if the device was mounted using its glabel. */
		if (match_glabel(devp, q)) {
			if (devp->mntpt != NULL &&
			    strcmp(devp->mntpt, mb[i].f_mntonname) == 0)
				return (devp->mntpt);
			free(devp->mntpt);
			if ((devp->mntpt = strdup(mb[i].f_mntonname)) == NULL)
				die("strdup()");
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
	if ((n = getmntinfo(&mb, MNT_NOWAIT)) == -1)
		die("getmntinfo()");
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
			die("realloc()");
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
	bool   has_video_ts, has_mpeg2, has_mpegav, has_svcd;
	bool   has_vcd, has_bdmv;
	struct ioc_toc_header tochdr;
        struct iso_directory_record *dp;
	struct iso_primary_descriptor *ip;
	struct ioc_read_toc_single_entry tocent;

	if (!scsi_has_media(path))
		return (-1);
	buf = NULL; type = ST_UNKNOWN;
	if ((fd = open(devpath(path), O_RDONLY)) == -1)
		goto error;
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
	if (strncmp(ip->id, ISO_STANDARD_ID, sizeof(ISO_STANDARD_ID) - 1) &&
	    strncmp(ip->id, ISO_SIERRA_ID, sizeof(ISO_SIERRA_ID) -1)) {
		/* No ISO9660 filesystem */
		goto done;
	}
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
	has_video_ts = has_mpeg2 = has_mpegav = false;
	has_svcd = has_vcd = has_bdmv = false;
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
			else if (!strncasecmp(dp->name, "BDMV", namelen))
				has_bdmv = true;
		}
		if (has_video_ts)
			type = ST_DVD;
		else if (has_mpeg2 && has_svcd)
			type = ST_SVCD;
		else if (has_mpegav && has_vcd)
			type = ST_VCD;
		else if (has_bdmv)
			type = ST_BLURAY;
		p	 += reclen;
		len	 -= reclen;
		dirtblsz -= reclen;
		if (reclen <= 0)
			break;
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
		if (scsi_has_media(devname)) {
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
	int    type;
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
	(void)snprintf(var, sizeof(var) - 1, "dev.umass.%d.%%location",
	    cd->sim_unit_number);
	cam_close_device(cd);
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

static bool
dev_check_exists(const char *dev)
{
	struct devlist_s *ep;

	dev = devbasename(dev);
	/* Check if we already have this device. */
	SLIST_FOREACH(ep, &devs, next) {
		if (strcmp(dev, ep->devp->dev + sizeof(_PATH_DEV) - 1) == 0) {
			/* Device already exists. */
			return (true);
		}
	}
	return (false);
}

static sdev_t *
add_ptp_device(const char *ugen)
{
	int	    i;
	sdev_t	    *devp;
	const char  *dev;
	struct stat sb;
	struct devlist_s *ep;

	if (dev_check_exists(ugen))
		return (NULL);
	dev = devbasename(ugen);
	if (devstat(ugen, &sb) == -1)
		return (NULL);
	if ((devp = malloc(sizeof(sdev_t))) == NULL)
		die("malloc()");
	if ((devp->dev = strdup(devpath(dev))) == NULL)
		die("strdup()");
	for (i = 0; i < nfstypes && fstype[i].id != PTPFS; i++)
		;
	devp->fs = &fstype[i];
	if ((devp->name = get_label(dev, devp->fs->name)) != NULL) {
		devp->name = strdup(devp->name);
		if (devp->name == NULL)
			die("strdup()");
	} else {
		devp->name = malloc(sizeof("Camera ()") + strlen(dev) + 1);
		if (devp->name == NULL)
			die("malloc()");
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
	devp->ejectable	  = false;
	devp->visible	  = true;
	devp->mntpt	  = NULL;
	devp->cmd_mounted = false;
	devp->dsbmd_mounted = false;

	if ((ep = malloc(sizeof(struct devlist_s))) == NULL)
		die("malloc()");
	ep->devp = devp;
	SLIST_INSERT_HEAD(&devs, ep, next);
	notifybc(devp, true);

	return (devp);
}

static sdev_t *
add_mtp_device(const char *ugen)
{
	int	    i;
	sdev_t	    *devp;
	const char  *dev;
	struct stat sb;
	struct devlist_s *ep;

	if (dev_check_exists(ugen))
		return (NULL);
	dev = devbasename(ugen);
	if (devstat(ugen, &sb) == -1)
		return (NULL);
	if ((devp = malloc(sizeof(sdev_t))) == NULL)
		die("malloc()");
	if ((devp->dev = strdup(devpath(dev))) == NULL)
		die("strdup()");

	for (i = 0; i < nfstypes && fstype[i].id != MTPFS; i++)
		;
	devp->fs = &fstype[i];
	if ((devp->name = get_label(dev, devp->fs->name)) != NULL) {
		devp->name = strdup(devp->name);
		if (devp->name == NULL)
			die("strdup()");
	} else {
		devp->name = malloc(sizeof("Camera ()") + strlen(dev) + 1);
		if (devp->name == NULL)
			die("malloc()");
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
	devp->ejectable	  = false;
	devp->visible	  = true;
	devp->mntpt	  = NULL;
	devp->cmd_mounted = false;
	devp->dsbmd_mounted = false;

	if ((ep = malloc(sizeof(struct devlist_s))) == NULL)
		die("malloc()");
	ep->devp = devp;
	SLIST_INSERT_HEAD(&devs, ep, next);

	devp->cmd_mounted = false;
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
	struct devlist_s *ep;

	if ((devp = malloc(sizeof(sdev_t))) == NULL)
		die("malloc()");
	/* Generate a fictive device name */
	if ((devp->dev = strdup("/dev/pseudo##")) == NULL)
		die("strdup()");
	(void)sprintf(devp->dev, "/dev/pseudo%02d", id++);
	/* Use the last part of mount point path for the name */
	for (p = strchr(mntpt, '\0'); *p != '/' && p != mntpt; p--)
		;
	if (*p == '/')
		p++;
	if ((devp->name = strdup(p)) == NULL)
		die("strdup()");
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
	devp->visible	  = true;
	devp->ejectable	  = false;
	devp->cmd_mounted = false;
	devp->dsbmd_mounted = false;

	if ((devp->mntpt = strdup(mntpt)) == NULL)
		die("strdup()");
	if ((ep = malloc(sizeof(struct devlist_s))) == NULL)
		die("malloc()");
	ep->devp = devp;
	SLIST_INSERT_HEAD(&devs, ep, next);

	notifybc(devp, true);

	return (devp);
}

static sdev_t *
add_device(const char *devname)
{
	int	    i, j, speed, fd;
	char	    *path, *realdev;
	sdev_t	    *devp, dev = { 0 };
	const char  *p;
	struct stat sb;
	struct devlist_s *ep;

	if (dev_check_exists(devname))
		return (NULL);
	devname = devbasename(devname);

	if ((dev.iface = iface_from_name(devname)) == NULL)
		return (NULL);
	/* Get full path to device */
	path = devpath(devname);
	if (dev.iface->type == IF_TYPE_CD || dev.iface->type == IF_TYPE_DA)
		dev.has_media = scsi_has_media(get_diskname(path));
	else
		dev.has_media = has_media(path);
	if ((dev.st = get_storage_type(devname)) != NULL) {
		if (dev.st->type == ST_MTP)
			return (add_mtp_device(devname));
		else if (dev.st->type == ST_PTP)
			return (add_ptp_device(devname));
		else if (is_parted(devname) && !match_part_dev(devname, 0)) {
			/*
			 * In most cases, we only want to add slices of
			 * partitioned disks. But there is a special case:
			 * ISO-FS. It is mountable by itself.
			 */
			fs_t *fs = getfs(devpath(devname));
			if ((fs == NULL) || (fs->id != CD9660))
				return (NULL); 
		}
	} else if (dev.iface->type != IF_TYPE_CD)
		return (NULL);
	if (dev.iface->type == IF_TYPE_CD) {
		/* Ignore devices like 'cd0a' */
		p = strchr(devname, '\0') - 1;
		if (strchr("abcdefgh", *p) != NULL)
			return (NULL);
	} 
	if (dev.iface->type == IF_TYPE_LVM) {
		realdev = get_lvm_dev(devname);
		if (realdev == NULL)
			return (NULL);
		if ((dev.realdev = strdup(realdev)) == NULL)
			die("strdup()");
		if (devstat(realdev, &sb) == -1)
			return (NULL);
	} else if (devstat(devname, &sb) == -1)
		return (NULL);
	if (!is_mountable(devname))
		return (NULL);
	if (dev.has_media)
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
	if (dev.iface->type == IF_TYPE_DA || dev.iface->type == IF_TYPE_CD ||
	    dev.iface->type == IF_TYPE_MD)
		dev.ejectable = true;
	else
		dev.ejectable = false;
	if ((devp = malloc(sizeof(sdev_t))) == NULL)
		die("malloc()");
	if ((devp->dev = strdup(path)) == NULL)
		die("strdup()");
	if (dev.fs != NULL && (p = get_label(devname, dev.fs->name)) != NULL) {
		if ((devp->name = strdup(p)) == NULL)
			die("strdup()");
	} else if ((devp->name = strdup(devname)) == NULL)
		die("strdup()");

	/*
	 * Get all glabels for this device. Drives with UFS can have more than
	 * one glabel: ufs/somename, or label/somename, and ufsid/id.
	 */
	for (i = j = 0; i < NGLBLPRFX; i++) {
		if ((p = get_geom_label(devname, glblprfx[i])) != NULL) {
			if ((devp->glabel[j++] = strdup(p)) == NULL)
				die("strdup()");
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
	devp->realdev     = dev.realdev;
	devp->has_media   = dev.has_media;
	devp->visible	  = false;
	devp->in_pollq	  = false;
	devp->ejectable   = dev.ejectable;
	devp->cmd_mounted = false;
	devp->dsbmd_mounted = false;

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
	if ((ep = malloc(sizeof(struct devlist_s))) == NULL)
		die("malloc()");
	ep->devp = devp;
	SLIST_INSERT_HEAD(&devs, ep, next);

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
	int j;
	struct devlist_s *ep;

	SLIST_FOREACH(ep, &devs, next) {
		if (ep->devp == devp)
			break;
	}
	if (ep == NULL)
		return;
	del_from_pollqueue(devp);
	if (devp->has_media && devp->visible)
		notifybc(devp, false);
	/*
	 * Try to remove the mount table entry if the device was removed
	 * without unmounting it first.
	 */
	if (is_mntpt(devp->mntpt)) {
		(void)unmount(devp->mntpt, MNT_FORCE);
		(void)rmntpt(devp->mntpt);
	}
	free(devp->mntpt);
	free(devp->dev);
	free(devp->name);
	free(devp->model);
	free(devp->realdev);

	for (j = 0; j < NGLBLPRFX && devp->glabel[j] != NULL; j++)
		free(devp->glabel[j]);
	free(devp);
	SLIST_REMOVE(&devs, ep, devlist_s, next);
	free(ep);
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
			die("libusb20_dev_open()");
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
					case USB_SUBCLASS_SFF:
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
                        die("libusb20_dev_close()");
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
	struct gconfig	 *conf;
	struct gprovider *pp;

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
	if (devp->iface->type == IF_TYPE_MD) {
		if ((error = detach_mddev(devp)) != 0)
			cliprint(cli, "E:command=eject:code=%d", error);
		else
			cliprint(cli, "O:command=eject");
		return (error);
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
	    0, 1, 0, SSD_FULL_SIZE, 100000);
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
			(void)scsi_has_media(disk);
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
			del_from_pollqueue(devp);
			notifybc(devp, false);
		}
	}
	return (error);
}

static int
attach_mddev(client_t *cli, const char *image)
{
	int             error, fd;
	gid_t		*gp;
	struct stat	sb;
	struct md_ioctl mdio;

	error = 0;
	(void)memset(&mdio, 0, sizeof(mdio));

	mdio.md_type	= MD_VNODE;
	mdio.md_version	= MDIOVERSION;
	mdio.md_options	= MD_AUTOUNIT| MD_CLUSTER | MD_COMPRESS;

	if ((mdio.md_file = realpath(image, NULL)) == NULL) {
		logprint("realpath(%s)", image);
		goto error;
	}
	if (stat(mdio.md_file, &sb) == -1) {
		logprint("stat(%s)", mdio.md_file);
		goto error;
	}
	if (!S_ISREG(sb.st_mode)) {
		error = ERR_NOT_A_FILE;
		goto error;
	}
	if (sb.st_uid != cli->uid) {
		for (gp = cli->gids; *gp != (gid_t)-1; gp++) {
			if (sb.st_gid == *gp)
				break;
		}
		if (*gp == (gid_t)-1 || !(S_IRGRP & sb.st_mode))
			error = ERR_PERMISSION_DENIED;
		if (!(S_IWGRP & sb.st_mode))
			mdio.md_options |= MD_READONLY;
	} else {
		if (!(S_IRUSR & sb.st_mode))
			error = ERR_PERMISSION_DENIED;
		if (!(S_IWUSR & sb.st_mode))
			mdio.md_options |= MD_READONLY;
	}
	if (error != 0)
		goto error;
	mdio.md_mediasize = sb.st_size;

	if (!kld_isloaded("g_md") && kld_load("geom_md") == -1) {
		logprint("kld_load(geom_md)");
		goto error;
	}
	if ((fd = open(_PATH_DEV MDCTL_NAME, O_RDWR, 0)) == -1) {
		logprint("open(%s%s)", _PATH_DEV, MDCTL_NAME);
		goto error;
	}
	if (ioctl(fd, MDIOCATTACH, &mdio) == -1) {
		logprint("ioctl(%s%s)", _PATH_DEV, MDCTL_NAME);
		goto error;
	}
	cliprint(cli, "O:command=mdattach");
	free(mdio.md_file);

	return (0);
error:
	cliprint(cli, "E:command=mdattach:code=%d",
	    error != 0 ? error : errno);
	free(mdio.md_file);

	return (-1);
}

static int
detach_mddev(sdev_t *devp)
{
	int             error, fd;
	struct md_ioctl mdio;

	error = 0;
	(void)memset(&mdio, 0, sizeof(mdio));
	if ((mdio.md_file = malloc(PATH_MAX)) == NULL)
		die("malloc()");
	(void)memset(mdio.md_file, 0, PATH_MAX);
	mdio.md_unit    = strtol(devbasename(devp->dev) + 2, NULL, 10);
	mdio.md_version = MDIOVERSION;
	if ((fd = open(_PATH_DEV MDCTL_NAME, O_RDWR, 0)) == -1) {
		error = errno;
		logprint("open(%s%s)", _PATH_DEV, MDCTL_NAME);
	} else if (ioctl(fd, MDIOCDETACH, &mdio) == -1) {
		error = errno;
		logprint("ioctl(%s%s, MDIOCDETACH)", _PATH_DEV, MDCTL_NAME);
		(void)close(fd);
	}
	free(mdio.md_file);

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

	if ((s = socket(PF_LOCAL, SOCK_SEQPACKET, 0)) == -1)
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

	if (socket == -1)
		return (-1);
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

	if (cli->s == -1)
		return;
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
	int	saved_errno;
	va_list	ap;
	struct clilist_s *ep;

	saved_errno = errno;
	SLIST_FOREACH(ep, &clis, next) {
		if (exclude != NULL && exclude->id == ep->cli->id)
			continue;
		if (ep->cli->s == -1)
			continue;
		va_start(ap, fmt);
		(void)vsnprintf(ep->cli->msg, sizeof(ep->cli->msg) - 2,
		    fmt, ap);
		(void)strcat(ep->cli->msg, "\n");
		(void)send_string(ep->cli->s, ep->cli->msg);
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
	struct clilist_s *ep;

	SLIST_FOREACH(ep, &clis, next)
		notify(ep->cli, devp, add);

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
	if ((n = client_readln(cli, &error)) > 0) {
		exec_cmd(cli, cli->buf);
		return (0);
	}
	if (n == 0)
		return (0);
	if (error == SOCK_ERR_IO_ERROR)
		logprint("client_readln() error. Closing client connection");
	/* Client disconnected or error. */
	return (-1);
}

static int
strtoargv(char *str, char **argv, size_t argvsz, size_t *argc)
{
	int    quote, esc;
	char   *start;
	size_t n;

	while (isspace(*str))
		str++;
	quote = n = esc = 0; start = str;
	for (; n < argvsz && *str != '\0'; str++) {
		if (*str == '"') {
			if (esc) {
				esc ^= 1;
			} else {
				quote ^= 1;
				(void)memmove(str, str + 1, strlen(str));
				str--;
			}
		} else if (*str == '\\') {
			if (!esc) {
				(void)memmove(str, str + 1, strlen(str));
				str--;
			}
			esc ^= 1;
		} else if (isspace(*str)) {
			if (esc) {
				esc ^= 1;
			} else if (!quote) {
				*str = '\0';
				while (isspace(str[1]))
					str++;
				argv[n++] = start; start = str + 1;
			}
		}
	}
	if (quote || esc)
		return (-1);
	if (str != start && n < argvsz)
		argv[n++] = start;
	*argc = n;

	return (0);
}

static void
catch_cmd_timeout(int signo)
{
	pthread_t tid = pthread_self();
	struct thrlist_s *ep;

	SLIST_FOREACH(ep, &cmdthreads, next) {
		if (ep->cmdthr->tid == tid && ep->cmdthr->timedout)
			longjmp(ep->cmdthr->jmpenv, 1);
	}
}

static cmdthread_t *
add_cmdthr(client_t *cli, struct command_s *cmd, size_t argc, const char **argv)
{
	size_t i;
	cmdthread_t	 *ct;
	struct thrlist_s *cep;

	if ((ct = malloc(sizeof(cmdthread_t))) == NULL ||
	    (cep = malloc(sizeof(struct thrlist_s))) == NULL)
		die("malloc()");
	if ((ct->argv = malloc((argc + 1) * sizeof(char *))) == NULL)
		die("malloc()");
	for (i = 0; i < argc; i++) {
		if ((ct->argv[i] = strdup(argv[i])) == NULL)
			die("strdup()");
	}
	ct->argv[i]  = NULL;
	ct->cli      = cli;
	ct->cmd	     = cmd;
	ct->timedout = false;
	cep->cmdthr  = ct;
	if (pthread_cond_init(&ct->cond, NULL) != 0)
		die("pthread_cond_init()");
	if (pthread_mutex_init(&ct->mtx, NULL) != 0)
		die("pthread_mutex_init()");
	SLIST_INSERT_HEAD(&cmdthreads, cep, next);

	return (ct);
}

static void
del_cmdthr(cmdthread_t *cmdthr)
{
	char **argv;
	struct thrlist_s *ep;

	SLIST_FOREACH(ep, &cmdthreads, next) {
		if (ep->cmdthr->tid == cmdthr->tid)
			break;
	}
	if (ep == NULL)
		return;
	pthread_cond_destroy(&ep->cmdthr->cond);
	pthread_mutex_destroy(&ep->cmdthr->mtx);
	argv = ep->cmdthr->argv;
	while (argv != NULL && *argv != NULL)
		free(*argv++);
	if (ep->cmdthr->argv != NULL)
		free(ep->cmdthr->argv);
	free(ep->cmdthr);
	SLIST_REMOVE(&cmdthreads, ep, thrlist_s, next);
}

static void
exec_cmd(client_t *cli, char *cmdstr)
{
	int    i, ret;
	char   *argv[12];
	sdev_t *devp;
	size_t argc;
	cmdthread_t	 *ct;
	struct timespec	 at;
	struct command_s *cp;

	(void)strtok(cmdstr, "\r\n");
	if (strlen(cmdstr) == 0) {
		/* Ignore empty strings */
		return;
	}
	if (strtoargv(cmdstr, argv, sizeof(argv) / sizeof(char *) - 1,
	    &argc) == -1) {
		cliprint(cli, "E:code=%d", ERR_SYNTAX_ERROR);
		return;
	}
	argv[argc] = NULL;
	for (cp = NULL, i = 0; cp == NULL && i < NCOMMANDS; i++) {
		if (argv[0] != NULL && strcmp(argv[0], commands[i].cmd) == 0)
			cp = &commands[i];
	}
	if (cp == NULL) {
		cliprint(cli, "E:command=%s:code=%d", argv[0],
		    ERR_UNKNOWN_COMMAND);
		return;
	}
	ct = add_cmdthr(cli, cp, argc - 1, (const char **)argv + 1);

	(void)pthread_mutex_lock(&ct->mtx);
	if (pthread_create(&ct->tid, NULL, cmd_thr, ct) != 0)
		die("pthread_create()");
	(void)clock_gettime(CLOCK_REALTIME, &at);
	at.tv_sec += dsbcfg_getval(cfg, CFG_CMDMAXWAIT).integer;
	/*
	 * If we are going to execute an external mount command, we need to
	 * add the value of CFG_PROCMAXWAIT to the timeout value.
	 */
	if (strcmp(argv[0], "mount") == 0 && argc >= 2 &&
	    (devp = lookup_dev(argv[1])) != NULL) {
		if (devp->fs->mntcmd != NULL || (devp->fs->mntcmd_u != NULL &&
		    dsbcfg_getval(cfg, CFG_USERMOUNT).boolean &&
		    usermount_set()))
			at.tv_sec += dsbcfg_getval(cfg, CFG_PROCMAXWAIT).integer;
	}
	ret = pthread_cond_timedwait(&ct->cond, &ct->mtx, &at);
	(void)pthread_mutex_unlock(&ct->mtx);

	if (ret == ETIMEDOUT) {
		cliprint(cli, "E:command=%s:code=%d", argv[0], ERR_TIMEOUT);
		ct->timedout = true;
		(void)pthread_kill(ct->tid, SIGALRM);
		del_cmdthr(ct);
		return;
	} else if (ret != 0) {
		/* This should not happen */
		die("pthread_cond_timedwait()");
	}
	del_cmdthr(ct);
}

static void *
cmd_thr(void *arg)
{
	sigset_t    sset;
	cmdthread_t *cmdthr = (cmdthread_t *)arg;

	sigfillset(&sset);
	sigdelset(&sset, SIGALRM);
	(void)pthread_sigmask(SIG_SETMASK, &sset, NULL);
	(void)signal(SIGALRM, catch_cmd_timeout);

	if (setjmp(cmdthr->jmpenv) != 0)
		return (NULL);
	/* Just for synchronizing with parent */
	(void)pthread_mutex_lock(&cmdthr->mtx);
	(void)pthread_mutex_unlock(&cmdthr->mtx);

	cmdthr->cmd->cmdf(cmdthr->cli, cmdthr->argv);
	(void)pthread_cond_signal(&cmdthr->cond);

	return (NULL);
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
		/* When mounting MTP devices via FUSE, the block size is 0 */
		if (s.f_bsize == 0)
			s.f_bsize = 512;
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
cmd_mdattach(client_t *cli, char **argv)
{
	if (argv[0] == NULL) {
		cliprint(cli, "E:command=mdattach:code=%d", ERR_SYNTAX_ERROR);
		return;
	}
	(void)attach_mddev(cli, argv[0]);
}

static void
cmd_quit(client_t *cli, char **argv)
{
	cli->s = -1;
}

static time_t
poll_mntbl()
{
	int n;
	static size_t bufsz = 0;
	static struct statfs *buf;

	if (bufsz == 0) {
		/* Init */
		while ((n = getfsstat(NULL, 0, MNT_NOWAIT)) == -1)
			(void)usleep(500000);
		bufsz = (n + 8) * sizeof(struct statfs);
		if ((buf = malloc(bufsz)) == NULL)
			die("malloc()");
	}
	if ((n = getfsstat(buf, bufsz, MNT_NOWAIT)) != -1) {
		while (n > 0 && n * sizeof(struct statfs) >= bufsz) {
			bufsz += 8 * sizeof(struct statfs);
			if ((buf = realloc(buf, bufsz)) == NULL)
				die("realloc()");
			if ((n = getfsstat(buf, bufsz, MNT_NOWAIT)) == -1)
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
	int	   i;
	bool	   found;
	sdev_t	   *devp;
	const char *q;
	struct devlist_s *ep;

	for (i = 0; i < nsb; i++) {
		q = devbasename(sb[i].f_mntfromname);
		/* Check for new FUSE device mounts */
		if (strncmp(q, "fuse", 4) == 0) {
			found = false;
			SLIST_FOREACH(ep, &devs, next) {
				 if (found)
					break;
				devp = ep->devp;
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
	int	j;
	bool	found;
	sdev_t *devp;
	struct devlist_s *ep, *ep_tmp;
	
	SLIST_FOREACH_SAFE(ep, &devs, next, ep_tmp) {
		devp = ep->devp;
		if (devp->st == NULL || devp->iface->type != IF_TYPE_FUSE)
			continue;
		for (j = 0, found = false; !found && j < nsb; j++) {
			if (strcmp(devp->mntpt, sb[j].f_mntonname) == 0)
				found = true;
		}
		if (!found)
			del_device(devp);
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
	int	   j;
	bool	   found;
	sdev_t	   *devp;
	const char *q, *mntpt;
	struct devlist_s *ep;
	
	SLIST_FOREACH(ep, &devs, next) {
		devp = ep->devp;
		if (devp->st == NULL || devp->iface->type == IF_TYPE_FUSE)
			continue;
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
					die("strdup()");
				devp->mounted = true;
				devp->dsbmd_mounted = false;
				cliprintbc(NULL, "M:dev=%s:mntpt=%s",
				    devp->dev, devp->mntpt);
			} else if (devp->mounted &&
			    strcmp(devp->mntpt, mntpt) != 0) {
				/* Remounted */
				devp->dsbmd_mounted = false;
				rmntpt(devp->mntpt);
				cliprintbc(NULL, "U:dev=%s:mntpt=%s",
				    devp->dev, devp->mntpt);
				free(devp->mntpt);
				devp->mntpt = strdup(mntpt);
				if (devp->mntpt == NULL)
					die("strdup()");
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

