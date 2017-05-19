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
#include <time.h>
#include <paths.h>
#include <errno.h>
#include <err.h>
#include <stdbool.h>

void
logprint(const char *fmt, ...)
{
	char	msgbuf[512], errstr[64], *tm;
	time_t	clock;
	va_list	ap;

	va_start(ap, fmt);
	(void)vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	clock = time(NULL); tm = ctime(&clock); (void)strtok(tm, "\n");
	(void)strerror_r(errno, errstr, sizeof(errstr));
	warnx("%s: %s on %s", msgbuf, errstr, tm);
}

void
logprintx(const char *fmt, ...)
{
	char	msgbuf[512], *tm;
	time_t	clock;
	va_list	ap;

	va_start(ap, fmt);
	(void)vsnprintf(msgbuf, sizeof(msgbuf), fmt, ap);
	clock = time(NULL); tm = ctime(&clock); (void)strtok(tm, "\n");
	warnx("%s on %s", msgbuf, tm);
}

/*
 * Returns the basename of the given device path.
 */
const char *
devbasename(const char *path)
{
	while (*path == '/')
		path++;
	if (strncmp(path, "dev", 3) == 0) {
		path += 3;
		while (*path == '/')
			path++;
	}
	return (path);
}

char *
devpath(const char *dev)
{
	static char   *path = NULL;
	static size_t  len  = 0;

	if (len <= strlen(dev) || path == NULL) {
		len = strlen(dev) + strlen(_PATH_DEV) + 10;
		if ((path = realloc(path, len)) == NULL)
			err(EXIT_FAILURE, "devpath(): realloc()");
	}
	if (strncmp(dev, _PATH_DEV, strlen(_PATH_DEV)) == 0)
		(void)strncpy(path, dev, len - 1);
	else
		(void)snprintf(path, len - 1, "%s%s", _PATH_DEV, dev);
	return (path);
}

bool
get_ugen_bus_and_addr(const char *ugen, int *bus, int *addr)
{
	int  n;
	char num[4];

	if (strncmp(ugen, "ugen", 4) != 0)
		return (false);
	ugen += 4;
	for (n = 0; n < 4 && isdigit(*ugen);)
		num[n++] = *ugen++;
	if (*ugen++ != '.')
		return (false);
	num[n] = '\0';
	*bus = strtol(num, NULL, 10);

	for (n = 0; n < 3 && isdigit(*ugen);)
		num[n++] = *ugen++;
	if (*ugen != '\0')
		return (false);
	num[n] = '\0';
	*addr = strtol(num, NULL, 10);
	
	return (true);
}

