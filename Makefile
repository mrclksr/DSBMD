PROGRAM	       	     = dsbmd
CFGFILE	       	     = ${PROGRAM}.conf
RCSCRIPT       	     = rc.d/${PROGRAM}
LOGFILE	       	     = /var/log/${PROGRAM}.log
PIDFILE	      	     = /var/run/${PROGRAM}.pid
SOCKETPATH     	     = /var/run/dsbmd.socket
PREFIX	      	    ?= /usr/local
BINDIR	       	     = ${PREFIX}/libexec
RCDIR	       	     = ${PREFIX}/etc/rc.d
CFGDIR	       	     = ${PREFIX}/etc
DOCSDIR		    ?= ${PREFIX}/share/doc/${PROGRAM}
DOCS		     = README
SCRIPTDIR	     = ${PREFIX}/libexec/dsbmd-scripts
SCRIPTS		     = scripts/mount_mtpfs.sh scripts/mount_ntfs.sh
SCRIPTS		    += scripts/mount_exfat.sh
SOURCES		     = ${PROGRAM}.c config.c dsbcfg/dsbcfg.c fs.c common.c
PROGRAM_FLAGS	     = -Wall ${CFLAGS} ${CPPFLAGS} -DPROGRAM=\"${PROGRAM}\"
PROGRAM_FLAGS	    += -DPATH_DSBMD_LOG=\"${LOGFILE}\"
PROGRAM_FLAGS	    += -DPATH_PID_FILE=\"${PIDFILE}\"
PROGRAM_FLAGS	    += -DPATH_DSBMD_SOCKET=\"${SOCKETPATH}\"
PROGRAM_FLAGS	    += -DPATH_CONFIG=\"${CFGDIR}/${CFGFILE}\"
PROGRAM_LIBS	     = -lgeom -lcam -lpthread -lutil -lkiconv -lusb
BSD_INSTALL_DATA    ?= install -m 0644
BSD_INSTALL_SCRIPT  ?= install -m 555
BSD_INSTALL_PROGRAM ?= install -s -m 555

all: ${PROGRAM} ${RCSCRIPT} ${CFGFILE}

${PROGRAM}: ${SOURCES}
	${CC} -o ${PROGRAM} ${PROGRAM_FLAGS} ${SOURCES} ${PROGRAM_LIBS}

${RCSCRIPT}: ${RCSCRIPT}.tmpl
	sed -e 's|@PATH_PROGRAM@|${BINDIR}/${PROGRAM}|g' \
	    -e 's|@PATH_PIDFILE@|${PIDFILE}|g' \
	< ${.ALLSRC} > ${RCSCRIPT}

${CFGFILE}: ${CFGFILE}.tmpl
	sed -e 's|@SCRIPTDIR@|${SCRIPTDIR}|g' \
	< ${.ALLSRC} > ${CFGFILE}

install: ${PROGRAM} ${RCSCRIPT} ${CFGFILE}
	${BSD_INSTALL_PROGRAM} ${PROGRAM} ${DESTDIR}${BINDIR}
	${BSD_INSTALL_SCRIPT} ${RCSCRIPT} ${DESTDIR}${RCDIR}
	${BSD_INSTALL_DATA} ${CFGFILE} ${DESTDIR}${CFGDIR}/${CFGFILE}.sample
	if [ ! -f ${DESTDIR}${CFGDIR}/${CFGFILE} ]; then \
		${BSD_INSTALL_DATA} ${CFGFILE} ${DESTDIR}${CFGDIR}; \
	fi
	-@mkdir ${DESTDIR}${DOCSDIR}
	-@mkdir ${DESTDIR}${SCRIPTDIR}
	${BSD_INSTALL_SCRIPT} ${SCRIPTS} ${DESTDIR}${SCRIPTDIR}
	${BSD_INSTALL_DATA} ${DOCS} ${DESTDIR}${DOCSDIR}

clean:
	-rm -f ${PROGRAM}
	-rm -f ${RCSCRIPT}
	-rm -f ${CFGFILE}

