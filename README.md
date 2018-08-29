
# ABOUT

**DSBMD**
is a media/filesystem type detecting daemon for FreeBSD that allows
clients to mount storage devices. It is configured to work out of the box.

# DESCRIPTION

**DSBMD**
watches the mount table for changes, monitors
devd(8)
events for new storage devices, polls CD/DVD drives and card readers for
media change events, determines media types, volume names, and filesystem
types. Mountable devices, changes in the mount table as well as device
add/remove events and altered states of mountable devices are presented to
clients. Clients can request
**DSBMD**
to mount, unmount, and eject media, or set the CD/DVD reading speed.

# FEATURES

Some features are:

*	Client authentication is handled using UNIX domain-socket credentials.
	Authorization can be defined on a user and/or group basis.

*	For each supported filesystem, mount flags or external mount commands can be
	defined.

*	Supported filesystems are: ISO-9660, FAT, NTFS, UFS, Ext2/3, Ext4, HFS+,
	exFAT, XFS, and Btrfs.

*	Mounts and unmounts not initiated though DSBMD are detected, and necessary
	action are taken.

*	Simple plain text protocol. DSBMD can be used and debugged using Telnet
	(telnet -u /var/run/dsbmd.socket) or Netcat (nc -U /var/run/dsbmd.socket).

*	Easy configuration through /usr/local/etc/dsbmd.conf

*	Support for FUSE

*	Support for memory disks (md)

*	Support for Linux LVM logical volumes through geom\_linux\_lvm(4)

*	Support for MTP devices

*	Support for PTP devices

*	Support for NVD devices

# OPTIONS

**-f**

> Run
> **DSBMD**
> in foreground.

# INSTALLATION

	# git clone https://github.com/mrclksr/DSBMD.git
	# git clone https://github.com/mrclksr/dsbcfg.git
	
	# cd DSBMD && make install

# WARNING

Running
**DSBMD**
together with
*hald*
is not recommended. Since both daemons access the same system resources and
execute similar actions, this might lead to malfunction.

# SETUP

In order to start DSBMD at boot time, add the following line to your
*/etc/rc.conf*:

	dsbmd_enable="YES"

Depending on your needs, install the FreeBSD ports
*fusefs-exfat*, *fusefs-gphotofs*, *fusefs-ntfs*, *fusefs-ext2*
(Ext2/3/4),
*fusefs-hfsfuse*, *fusefs-lkl*
(BTRFS, Ext4, and XFS), and
*fusefs-simple-mtpfs*.
**DSBMD**
comes with predefined commands in
*dsbmd.conf*
that use these ports to mount the corresponding filesystems.

For further configuration, see
*dsbmd.conf*.

## Mounting as regular user

If you want
**DSBMD**
to mount storage devices as regular user who initiated the
mount command, set

	usermount = true

in
*dsbmd.conf*,
and set
the
*sysctl*
variable
*vfs.usermount*
to 1:

	sysctl vfs.usermount=1

To make this setting permanent, add

	vfs.usermount=1

to
*/etc/sysctl.conf*

## Automount

Configure
**DSBMD**
for mounting as regular user (see above). This will allow you to unmount
automounted media without special privileges. Install
*sysutils/dsbmc-cli*
and start

	dsbmc-cli -a

manually as regular user, or add the command

	dsbmc-cli -a&

to your shell's rc file, or to your window manager's autostart file.

# FILES USED

*/var/run/dsbmd.socket*

> UNIX domain socket

*/usr/local/etc/dsbmd.conf*

> Configuration file

*/var/log/dsbmd.log*

> Logfile

# DSBMD PROTOCOL SPECIFICATION

## 1.0 CLIENT SIDE

## 1.1 CONNECTION

If a client WITHOUT permission connects,
**DSBMD**
sends an error message with code
`ERR_PERMISSION_DENIED (258)`,
and terminates the connection.

If a client WITH permission connects,
**DSBMD**
sends a list of zero or more devices using device add messages
(2.5.1). The list is terminated by sending a
'='
on a line by itself.

## 1.2 COMMANDS

## General command format

**command**
\[option \[*arg*]]
\[option \[*arg*]] ... &lt;newline&gt;

**DSBMD**
sends a reply message for any sent known or unknown command. Between
the transmission of the command and the reception of the command reply
message, multiple information and/or device add/remove messages (2.1) can
occur.

**DSBMD**
processes each client's commands synchronously, that is, the commands
will be processed in the same order as they where received. After a command's
reply message was sent, the next command will be processed.
**DSBMD**
supports the following commands:

**mount** *&lt;device name&gt;*

> Mount the given device.

**unmount** \[**-f**] *&lt;device name&gt;*

> If the
> **-f**
> switch is specified, unmounting will be enforced.

**eject** \[**-f**] *&lt;device name&gt;*

> This command unmounts and ejects the inserted media. If the
> **-f**
> switch is specified, unmounting and ejecting of the media will be enforced.

**speed** *&lt;device name&gt;* *&lt;speed&gt;*

> Sets the maximum reading speed of the CD/DVD device.

**size** *&lt;device name&gt;*

> This command asks
> **DSBMD**
> for the capacity of a disk.
> **DSBMD**
> will return the total size in bytes, and if the device is mounted, it
> will also return the number of used and free bytes.

**mdattach** *&lt;/path/to/image&gt;*

> Create a memory disk to access the given disk image.

# 2.0 DAEMON SIDE

## 2.1 GENERAL DSBMD MESSAGE FORMAT

&lt;message type&gt;:&lt;keyword&gt;=&lt;value&gt;:...:&lt;keyword&gt;=&lt;value&gt;&lt;newline&gt;

## 2.2 DSBMD MESSAGE TYPES

	*Message type*  *Meaning*  
	+               A device/media was added  
	-               A device/media was removed  
	M               A device/media was mounted  
	U               A device/media was unmounted  
	V               The reading speed of a CD/DVD was changed.  
	E               Command failed.  
	O               Command execution was successful.  
	S               Shutdown

## 2.3 KEYWORDS AND VALUES

	*Keyword*       *Value*  
	command         mount, unmount, speed, eject, size  
	code            errno number (< 257) or a special error code (>= 257)  
	dev             Device name  
	mntpt           Mount point  
	speed           Max. CD/DVD reading speed.  
	mediasize       Total capacity in bytes of a media  
	used            Number of used bytes of a media  
	free            Number of free bytes of a media  
	type            Device/media type: HDD, AUDIOCD, DVD, VCD, USBDISK, SVCD,
	DATACD, MMC, MTP, PTP  
	cmds            A comma (',')
	separated list of supported device commands.  
	mntcmderr       Numerical return value of external mount command.

## 2.4 ERROR CODES

	*Code*          *Meaning*  
	257             Device already mounted  
	258             Permission denied  
	259             Device not mounted  
	260             Device busy  
	261             No such device  
	262             Max. number of connections reached  
	263             Not ejectable  
	264             Unknown command  
	265             Unknown option  
	266             Syntax error  
	267             No media  
	268             Unknown filesystem  
	269             Unknown error  
	270             Mount command failed  
	271             Invalid Argument  
	272             Command string too long  
	273             Invalid command string  
	274             Timeout  
	275             Not a regular file

## 2.5 DSBMD MESSAGES

## 2.5.0 BROADCAST MESSAGES

## Device added (+)

	+:dev=<devname>:type=<devtype>:cmds=<command list>
	      [:volid=<volid>][:mntpt=<mounted on>][:speed=<speed>]

## Device removed (-)

	-:dev=<devname>

## Reading speed changed (V)

If the speed of a CDROM device was changed, the following message will be
sent to all connected clients, except for the client who sent the command.

	V:dev=<devname>:speed=<speed>

## Device mounted (M)

If a device was mounted, the following message will be sent to all connected
clients, exept for the client who sent the command.

	M:dev=<devname>:mntpt=<mounted on>

## Device unmounted (U)

If a device was unmounted, the following message will be sent to all connected
clients, except for the client who sent the command.

	U:dev=<devname>:mntpt=<mounted on>

## Daemon shutdown (S)

If the daemon was terminated, it sends the following message to all connected
clients:

	S

## 2.5.1 COMMAND REPLY MESSAGES

## Error message (E)

	E:code=<error code>[:command=<executed command>]

## Success message (O)

	O:command=<executed command>[:keyword=value] ...

If a device was successfully mounted,
**DSBMD**
replies with the following
message:

	O:command=mount:dev=<devname>:mntpt=<mounted on>

If a device was successfully unmounted,
**DSBMD**
replies with the following
message:

	O:command=unmount:dev=<devname>:mntpt=<mounted on>

If the capacity of a disk device was requested,
**DSBMD**
sends the following
message:

	O:command=size:dev=<devname>:mediasize=<size>:used=<used>:free=<free>

Where
'size'
is the storage capacity in bytes,
'used'
is the number of used and
'free'
is the number of free bytes. If the device/media is not mounted,
'free'
and
'used'
are 0.

 \- August 30, 2018
