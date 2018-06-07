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
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <err.h>
#include <pwd.h>
#include <grp.h>
#include "dsbcfg.h"

static int	write_var(dsbcfg_var_t *, FILE *);
static int	parse_line(char *, dsbcfg_vardef_t *, int, dsbcfg_var_t *);
static int	var_set_defaults(dsbcfg_var_t *, dsbcfg_vardef_t *, int);
static int	open_cfg_file(const char *, const char *);
static bool	is_label(const char *);
static char	*readln(void);
static char	*cfgpath(const char *, const char *);
static char	*cutok(char *, bool *);
static char	*escape_str(const char *);
static char	*strdupstrcat(char **, char *);
static char	**add_string(char ***, const char *);
static void	close_cfg_file(void);
static void	seterr(int, const char *, ...);
static void	free_node(dsbcfg_t *);
static dsbcfg_t	*new_config_node(int);

#define NERRCODES (sizeof(errtbl) / sizeof(errtbl[0]))

static struct errtbl_s {
	int	   code;
	const char *msg;
} errtbl[] = {
	{ DSBCFG_ERR_SYS_ERROR,    "Fatal error"		    },
	{ DSBCFG_ERR_INCOMPLETE,   "Incomplete escape sequence"     },
	{ DSBCFG_ERR_UNTERMINATED, "Unterminated quoted string"     },
	{ DSBCFG_ERR_MISSING_SEP,  "Missing '='"		    },
	{ DSBCFG_ERR_MISSING_VAL,  "Missing value"		    },
	{ DSBCFG_ERR_UNKNOWN_VAR,  "Unknown variable"		    },
	{ DSBCFG_ERR_PATH_EXCEED,  "Path name too long"		    },
	{ DSBCFG_ERR_DUPLICATED,   "Duplicated config file section" }
};

static struct error_s {
	int  lineno;			 /* Current line number. */
	int  errcode;			 /* error code for error table. */
	int  _errno;			 /* Saved errno. */
	char prfx[1024];		 /* function name/message. */
	char *file;
} _error;

static struct parser_s {
	int  lineno;			 /* Current line number. */
	int  bufsz;			 /* Total capacity of lnbuf */
	int  rd;			 /* # of bytes in lnbuf */
	int  slen;			 /* Length of next to return str. */
	bool needline;
	char file[_POSIX_PATH_MAX * 3];	 /* File name . */
	char *lnbuf;			 /* Line buffer for readln(). */
	char *pbuf;
	FILE *fp;
} parser;

void
dsbcfg_printerr()
{
	unsigned int i;

	if (_error.errcode == -1)
		return;
	for (i = 0; i < NERRCODES && errtbl[i].code != _error.errcode; i++)
		;
	if (i == NERRCODES)
		warnx("Unknown error code");
	else {
		if (_error.errcode & DSBCFG_ERR_SYNTAX_ERROR)
			(void)fprintf(stderr, "Syntax error: ");
		else if (_error.errcode == DSBCFG_ERR_SYS_ERROR &&
		    _error._errno != ENOENT)
			(void)fprintf(stderr, "Fatal: ");
		if (_error.prfx[0] != '\0')
			(void)fprintf(stderr, "%s: ", _error.prfx);
		(void)fprintf(stderr, "%s", errtbl[i].msg);
		if (_error.errcode == DSBCFG_ERR_SYS_ERROR) {
			(void)fprintf(stderr, ": %s\n",
			    strerror(_error._errno));
			errno = _error._errno;
			/* Not config file related, so return here. */
			return;
		} else if (_error.lineno > 0) {
			(void)fprintf(stderr, ", in file %s, line %d\n",
			    _error.file, _error.lineno);
		} else
			(void)fprintf(stderr, "\n");
	}
	errno = _error._errno;
}

const char *
dsbcfg_strerror()
{
	unsigned int i;
	static char strbuf[1024 + sizeof(_error.prfx)], *p;
	
	p = strbuf; *p = '\0';
	if (_error.errcode == -1)
		return (strbuf);
	for (i = 0; i < NERRCODES && errtbl[i].code != _error.errcode; i++)
		;
	if (i == NERRCODES)
		return (strncpy(strbuf, "Unknown error code", sizeof(strbuf)));
	else {
		if (_error.errcode & DSBCFG_ERR_SYNTAX_ERROR) {
			(void)snprintf(p, sizeof(strbuf) - strlen(p) - 1,
			    "Syntax error: ");
		} else if (_error.errcode == DSBCFG_ERR_SYS_ERROR &&
		    _error._errno != ENOENT) {
			(void)snprintf(p, sizeof(strbuf) - strlen(p) - 1,
			    "Fatal: ");
		}
		if (_error.prfx[0] != '\0') {
			(void)snprintf(p + strlen(p),
			    sizeof(strbuf) - strlen(p) - 1,
			    "%s: ", _error.prfx);
		}
		(void)snprintf(p + strlen(p), sizeof(strbuf) - strlen(p) - 1,
		    "%s", errtbl[i].msg);
		if (_error.errcode == DSBCFG_ERR_SYS_ERROR) {
			(void)snprintf(p + strlen(p),
			    sizeof(strbuf) - strlen(p) - 1, ": %s\n",
			    strerror(_error._errno));
			errno = _error._errno;
			/* Not config file related, so return here. */
			return (strbuf);
		} else if (_error.lineno > 0) {
			(void)snprintf(p + strlen(p),
			    sizeof(strbuf) - strlen(p) - 1,
			    ", in file %s, line %d\n", _error.file,
			    _error.lineno);
		} else
			(void)snprintf(p + strlen(p),
			    sizeof(strbuf) - strlen(p) - 1, "\n");
	}
	errno = _error._errno;

	return (strbuf);
}

static void
seterr(int errcode, const char *msg, ...)
{
	va_list ap;

	_error.file    = parser.file;
	_error.lineno  = parser.lineno;
	_error._errno  = errno;
	_error.errcode = errcode;
	_error.prfx[0] = '\0';

	if (msg != NULL) {
		va_start(ap, msg);
		(void)vsnprintf(_error.prfx, sizeof(_error.prfx), msg, ap);
	}
}

/*
 * Creates the dir ~/.config/DSB, and if 'dir' is not NULL, it creates
 * ~/.config/DSB/dir. On success, dsbcfg_mkdir returns the complete path.
 */
char *
dsbcfg_mkdir(const char *dir)
{
	int	      len;
	char	      *path, *p, *q;
	struct stat   sb;
	struct passwd *pw;

	if ((pw = getpwuid(getuid())) == NULL) {
		seterr(DSBCFG_ERR_SYS_ERROR,
		    "Couldn't find you in the password file");
		return (NULL);
        }
	endpwent();

	len = sizeof(PATH_DSB_CFG_DIR) + strlen(pw->pw_dir) + 4;
	if (dir != NULL)
		len += strlen(dir);
	if ((path = malloc(len)) == NULL)
		return (NULL);
	(void)snprintf(path, len, "%s/", pw->pw_dir);
	for (p = PATH_DSB_CFG_DIR, q = path + strlen(path); *p != '\0';) {
		while (*p != '\0' && *p != '/')
			*q++ = *p++;
		if (*p == '/')
			p++;
		*q++ = '/'; *q = '\0';
		if (stat(path, &sb) == -1) {
			if (errno != ENOENT) {
				seterr(DSBCFG_ERR_SYS_ERROR, "stat()");
				return (NULL);
			}
			if (mkdir(path, S_IRWXU) == -1) {
				seterr(DSBCFG_ERR_SYS_ERROR, "mkdir()");
				return (NULL);
			}
		}
	}
	if (dir != NULL) {
		(void)strncat(path, dir, len - strlen(path) - 1);
		if (stat(path, &sb) == -1) {
			if (errno != ENOENT) {
				seterr(DSBCFG_ERR_SYS_ERROR, "stat()");
				return (NULL);
			}
			if (mkdir(path, S_IRWXU) == -1) {
				seterr(DSBCFG_ERR_SYS_ERROR, "mkdir()");
				return (NULL);
			}
		}
	} else
		*--q = '\0'; /* Remove trailing '/' */
	return (path);
}

/*
 * Returns the full path to config file. If 'file' begins with a '/' (full
 * path), cfgpath() returns that path.
 *
 * If file is not a full path, cfgpath() returns
 * <config base dir>/<subdir>/<file> if subdir != NULL, and
 * <config base dir>/<file> if subdir == NULL.
 */
static char *
cfgpath(const char *subdir, const char *file)
{
	struct passwd *pw;
	
	if (*file != '/') {
		if ((pw = getpwuid(getuid())) == NULL) {
			seterr(DSBCFG_ERR_SYS_ERROR,
			    "Couldn't find you in the password file");
			return (NULL);
		}
		endpwent();
	}
	if (strlen(subdir != NULL ? subdir : "") + strlen(file) +
	    (*file != '/' ? strlen(PATH_DSB_CFG_DIR) : 0)       +
	    4 > sizeof(parser.file)) {
		seterr(DSBCFG_ERR_PATH_EXCEED, NULL);
		return (NULL);
	}
	if (*file != '/') {
		(void)snprintf(parser.file, sizeof(parser.file),
		    subdir != NULL ? "%s/%s/%s/%s" : "%s/%s%s/%s", pw->pw_dir,
		    PATH_DSB_CFG_DIR, subdir != NULL ? subdir : "", file);
	} else
		(void)strncpy(parser.file, file, sizeof(parser.file));
	return (parser.file);
}

dsbcfg_t *
dsbcfg_read(const char *subdir, const char *file, dsbcfg_vardef_t *vardefs,
	    int nvardefs)
{
	char	 *ln;
	dsbcfg_t *cfg, *cp;

	errno = 0; cfg = NULL;
	if (open_cfg_file(subdir, file) == -1)
		return (NULL);
	/*
	 * Get all global variables, that is, variables before
	 * the first labeled block.
	 */
	while ((ln = readln()) != NULL && !is_label(ln)) {
		while (isspace(*ln))
			ln++;
		if (!*ln || *ln == '#')
			continue;
		if (cfg == NULL) {
			cp = cfg = new_config_node(nvardefs);
			if (cfg == NULL)
				goto error;
			if (var_set_defaults(cp->vars, vardefs, nvardefs) == -1)
				return (NULL);
		}
		(void)strtok(ln, "\n");
		if (parse_line(ln, vardefs, nvardefs, cp->vars) == -1)
			goto error;
	}
	if (ln == NULL) {
		if (cfg == NULL) {
			/* Empty config file. */
			if ((cfg = new_config_node(nvardefs)) == NULL)
				goto error;
			if (var_set_defaults(cfg->vars, vardefs,
			    nvardefs) == -1)
				return (NULL);
		}
 		close_cfg_file(); return (cfg);
	}
	for (; ln != NULL; ln = readln()) {
		if (is_label(ln)) {
			(void)strtok(ln, ":");
			if (cfg != NULL && dsbcfg_getnode(cfg, ln) != NULL) {
				seterr(DSBCFG_ERR_DUPLICATED,
				    "Section '%s'", ln);
				goto error;
			}
			if (cfg != NULL) {
				cp->next = new_config_node(nvardefs);
				if (cp->next == NULL)
					goto error;
				cp = cp->next;
			} else {
				if ((cfg = new_config_node(nvardefs)) == NULL)
					goto error;
				cp = cfg;
			}
			if ((cp->label = strdup(ln)) == NULL) {
				seterr(DSBCFG_ERR_SYS_ERROR, "strdup()");
				goto error;
			}
			if (var_set_defaults(cp->vars, vardefs, nvardefs) == -1)
				return (NULL);
		} else {
			(void)strtok(ln, "\n");
			if (parse_line(ln, vardefs, nvardefs, cp->vars) == -1)
				goto error;
		}
	}
	close_cfg_file();
	return (cfg);
error:
	dsbcfg_free(cfg); close_cfg_file();
	return (NULL);
}

char **
dsbcfg_list_to_strings(const char *str, bool *error)
{
	char *buf, *p, **v;

	*error = false;
	if (str == NULL)
		return (NULL);
	if ((buf = strdup(str)) == NULL) {
		seterr(DSBCFG_ERR_SYS_ERROR, "strdup()");
		return (NULL);
	}
	for (v = NULL, p = buf; (p = cutok(p, error)) != NULL; p = NULL) {
		if (add_string(&v, p) == NULL) {
			free(buf); free(v);
			return (NULL);
		}
	}
	free(buf);
	return (*error ? NULL : v);
}

dsbcfg_t *
dsbcfg_new(const char *label, dsbcfg_vardef_t *vardefs, int nvardefs)
{
	dsbcfg_t *cfg;

	if ((cfg = new_config_node(nvardefs)) == NULL)
		goto error;
	if (label != NULL) {
		if ((cfg->label = strdup(label)) == NULL) {
			seterr(DSBCFG_ERR_SYS_ERROR, "strdup()");
			goto error;
		}
	}
	if (var_set_defaults(cfg->vars, vardefs, nvardefs) == -1)
		goto error;
	return (cfg);
error:
	dsbcfg_free(cfg);
	return (NULL);
}

void
dsbcfg_delnode(dsbcfg_t **cfg, const char *label)
{
	dsbcfg_t *cp, *prev;
	
	if (label == NULL) {
		if ((*cfg)->label != NULL)
			return;
		cp = (*cfg)->next, free_node(*cfg), *cfg = cp;
		return;
	}
	for (cp = prev = *cfg; cp != NULL; cp = cp->next) {
		if (cp->label != NULL && !strcmp(cp->label, label)) {
			prev->next = cp->next, free_node(cp);
			return;
		} else
			prev = cp;
	}
}

dsbcfg_t *
dsbcfg_getnode(dsbcfg_t *cfg, const char *label)
{
	for (; cfg != NULL; cfg = cfg->next) {
		if (label == NULL && cfg->label == NULL)
			return (cfg);
		if (cfg->label != NULL && !strcmp(cfg->label, label))
			return (cfg);
	}
	return (NULL);
}

void
dsbcfg_free(dsbcfg_t *cfg)
{
	dsbcfg_t *cp, *next;

	for (cp = cfg; cp != NULL; cp = next)
		next = cp->next, free_node(cp);
}

static void
free_node(dsbcfg_t *node)
{
	int    i;
	char **pp;

	free(node->label);
	for (i = 0; i < node->nvars && node->vars != NULL; i++) {
		if (node->vars[i].type == DSBCFG_VAR_STRINGS) {
			for (pp = node->vars[i].val.strings;
			     pp != NULL && *pp != NULL; pp++)
				free(*pp);
			free(node->vars[i].val.strings);
		} else if (node->vars[i].type == DSBCFG_VAR_STRING)
			free(node->vars[i].val.string);
	}
	free(node->vars); free(node);
}

dsbcfg_t *
dsbcfg_addnode(dsbcfg_t *cfg, const char *label, dsbcfg_vardef_t *vardefs,
	       int ndefs)
{
	dsbcfg_t *cp;

	if (dsbcfg_getnode(cfg, label) != NULL) {
		seterr(DSBCFG_ERR_DUPLICATED,
		    label == NULL ? "Global section%s" : "Section '%s'",
		    label == NULL ? "" : label);
		return (NULL);
	}
	for (cp = cfg; cp != NULL && cp->next != NULL; cp = cp->next)
		;
	if (cp == NULL)
		return (NULL);
	if ((cp->next = new_config_node(ndefs)) == NULL)
		return (NULL);
	cp = cp->next;
	if ((cp->label = strdup(label)) == NULL) {
		seterr(DSBCFG_ERR_SYS_ERROR, "strdup()");
		return (NULL);
	}
	if (var_set_defaults(cp->vars, vardefs, ndefs) == -1)
		return (NULL);
	return (cp);
}

int
dsbcfg_setval(dsbcfg_t *node, int vid, dsbcfg_val_t val)
{
	char **pp;

	if (node->vars[vid].type == DSBCFG_VAR_STRING) {
		free(node->vars[vid].val.string);
		if ((node->vars[vid].val.string = strdup(val.string)) == NULL) {
			seterr(DSBCFG_ERR_SYS_ERROR, "strdup()");
			return (-1);
		}
	} else if (node->vars[vid].type == DSBCFG_VAR_STRINGS) {
		for (pp = node->vars[vid].val.strings;
		     pp != NULL && *pp != NULL; pp++)
			free(*pp);
		free(node->vars[vid].val.strings);
		node->vars[vid].val.strings = NULL;
		for (pp = val.strings; pp != NULL && *pp != NULL; pp++) {
			if (add_string(&node->vars[vid].val.strings, *pp)
			    == NULL)
				return (-1);
		}
	} else if (node->vars[vid].type == DSBCFG_VAR_INTEGER) {
		node->vars[vid].val.integer = val.integer;
	} else if (node->vars[vid].type == DSBCFG_VAR_BOOLEAN) {
		node->vars[vid].val.boolean = val.boolean;
	}
	return (0);
}

/*
 * Extends the string vector at *strv by the given string and terminates
 * the vector with a NULL-pointer.
 *
 * Returns the new string vector.
 */
static char **
add_string(char ***strv, const char *str)
{       
        static int    n;
        static char **p;

	if (*strv == NULL)
		n = 0;
	else {
		for (p = *strv, n = 0; p[n] != NULL; n++)
			;
	}
	n += 2;
	if ((p = realloc(*strv, n * sizeof(char *))) == NULL)
		goto error;
	*strv = p;
	if ((p[n - 2] = strdup(str)) == NULL)
		goto error;
	p[n - 1] = NULL;

	return (p);
error:
	seterr(DSBCFG_ERR_SYS_ERROR, "add_string()");
	for (p = *strv; p != NULL && *p != NULL; p++)
		free(*p);
	return (NULL);
}

static char *
strdupstrcat(char **buf, char *str)
{
	char   *p;
	size_t len;

	len = strlen(str) + 1;
	if (*buf != NULL)
		len += strlen(*buf);
	if ((p = realloc(*buf, len)) == NULL) {
		seterr(DSBCFG_ERR_SYS_ERROR, "realloc()");
		return (NULL);
	}
	*buf = p;
	return (strcat(p, str));
}

static char *
escape_str(const char *str)
{
	char *p, *esc;

	if ((esc = malloc(2 * strlen(str) + 1)) == NULL) {
		seterr(DSBCFG_ERR_SYS_ERROR, "malloc()");
		return (NULL);
	}
	for (p = esc; *str != '\0'; str++) {
		if (*str == '"' || *str == '\\')
			*p++ = '\\';
		*p++ = *str;
	}
	*p = '\0';

	return (esc);
}

/*
 * Extracts the first (str != NULL) or the next (str == NULL) token from a
 * comma  separated  list  of  (quoted) strings, while respecting the
 * escape rules.
 *
 * Returns the start address of the token, or NULL if the string is empty,
 * or a syntax error was found.
 */
static char *
cutok(char *str, bool *error)
{
	static int  esc, quote;
	static char *p, *q, *start = NULL;

	if (str != NULL) {
		free(parser.pbuf);
		parser.needline = false;
		parser.pbuf = start = strdup(str);
		if (parser.pbuf == NULL) {
			*error = true;
			seterr(DSBCFG_ERR_SYS_ERROR, "strdup()");
			return (NULL);
		}		
	} else if (parser.needline) {
		parser.needline = false;
		if ((p = readln()) == NULL) {
			if (_error.errcode > 0) {
				*error = true; return (NULL);
			}
			/* Ignore '\' at the end of the last line. */
			return (cutok(NULL, error));
		}
		(void)strtok(p, "\n");
		if (*p == '\0')
			/* Empty line */
			return (cutok(NULL, error));
		/* Ignore trailing spaces and tabs. */
		for (q = p; isspace(*q); q++)
			;
		if ((start = strdupstrcat(&parser.pbuf, q)) == NULL) {
			*error = true; return (NULL);
		}
	}
	/* Check if line ends with a '\' */
	for (esc = 0, p = parser.pbuf; *p != '\0'; p++) {
		if (*p == '\\')
			esc ^= 1;
		else if (esc)
			esc ^= 1;
	}
	if (esc) {
		/* Current line ends with a '\'. Concatinate next line. */
		p[-1] = '\0';
		parser.needline = true;
		return (cutok(NULL, error));
	} else
		parser.needline = false;
	while (*start != '\0' && isspace(*start))
		start++;
	if (*start == '"') {
		start++; quote = 1;
	} else
		quote = 0;
	if (*start == '\0') {
		if (quote == 1) {
			seterr(DSBCFG_ERR_UNTERMINATED, NULL);
			*error = true;
		} else
			*error = false;
		return (NULL);
	}
	*error = true;
	for (p = str = start; *str != '\0'; str++) {
		if (*str == '\\') {
			*p++ = *++str;
		} else if (*str == '"') {
			quote ^= 1;
		} else if (!quote) {
			if (*str == '#') {
				*p = '\0'; p = start; start = str;
				return (p);
			} if (isspace(*str)) {
				continue;	
			} else if (*str == ',') {
				*p++ = '\0'; p = start; start = str + 1;
				*error = false;
				return (p);
			} else
				*p++ = *str;
		} else
			*p++ = *str;
	}
	*p = '\0'; p = start; start = str;
	if (quote == 1) {
		seterr(DSBCFG_ERR_UNTERMINATED, NULL);
		return (NULL);
	}
	*error = false;
	return (p);
}

static bool
is_label(const char *str)
{
	const char *p;

	for (p = str; isspace(*p); p++)
		;
	if (*p == '#')
		return (false);
	if (!isspace(*str) && *str != ':') {
		if ((p = strchr(str, ':')) != NULL) {
			while (isspace(*(++p)))
				;
			if (*p == '\0' || *p == '#')
				/* Match. */
				return (true);
		}
	}
	/* No match. */
        return (false);
}

static char *
readln()
{
	int		 i, n;
	char		*p;
	struct parser_s *ps = &parser;

	if (ps->lnbuf == NULL) {
		if ((ps->lnbuf = malloc(_POSIX2_LINE_MAX)) == NULL)
			return (NULL);
		ps->bufsz = _POSIX2_LINE_MAX;
	}
	n = 0;
	do {
		ps->rd += n;
		if (ps->slen > 0) {
			for (i = 0; i < ps->rd - ps->slen; i++)
				ps->lnbuf[i] = ps->lnbuf[i + ps->slen];
		}
		ps->rd  -= ps->slen;
		ps->slen = 0;
		for (i = 0; i < ps->rd && ps->lnbuf[i] != '\n'; i++)
			;
		if (i < ps->rd && ps->lnbuf[i] == '\n') {
			ps->slen = i + 1;
			if (ps->slen >= ps->bufsz - 1)
				ps->slen = ps->rd = 0;
			ps->lnbuf[i] = '\0'; ps->lineno++;
			return (ps->lnbuf);
		}
		if (ps->rd >= ps->bufsz - 1) {
			p = realloc(ps->lnbuf, ps->bufsz + _POSIX2_LINE_MAX);
			if (p == NULL) {
				seterr(DSBCFG_ERR_SYS_ERROR, "realloc()");
				return (NULL);
			}
			ps->lnbuf  = p;
			ps->bufsz += _POSIX2_LINE_MAX;
		}
	} while ((n = fread(ps->lnbuf + ps->rd, 1,
	    ps->bufsz - ps->rd - 1, ps->fp)) > 0);
	if (ferror(ps->fp)) {
		seterr(DSBCFG_ERR_SYS_ERROR, "fread()");
		return (NULL);
	}
	if (ps->rd > 0) {
		ps->lnbuf[ps->rd] = '\0';
		ps->slen = ps->rd = 0; ps->lineno++;
		return (ps->lnbuf);
	}
	ps->slen = ps->rd = 0;

	return (NULL);
}

static int
var_set_defaults(dsbcfg_var_t *vars, dsbcfg_vardef_t *vardefs, int nvardefs)
{
	int    i, id;
	char **pp;
	
	for (i = 0; i < nvardefs; i++) {
		id = vardefs[i].id;
		vars[id].name = vardefs[i].name;
		vars[id].type = vardefs[i].type;

		if (vardefs[i].type == DSBCFG_VAR_STRING &&
		    vardefs[i].dflt.string != NULL) {
			vars[id].val.string = strdup(vardefs[i].dflt.string);
			if (vars[id].val.string == NULL) {
				seterr(DSBCFG_ERR_SYS_ERROR, "strdup()");
				return (-1);
			}
		} else if (vardefs[i].type == DSBCFG_VAR_STRINGS) {
			for (pp = vardefs[i].dflt.strings;
			     pp != NULL && *pp != NULL; pp++) {
				if (add_string(&vars[id].val.strings, *pp)
				    == NULL)
					return (-1);
			}
		} else
			vars[id].val = vardefs[i].dflt;
	}
	return (0);
}

static int
parse_line(char *str, dsbcfg_vardef_t *vardefs, int nvardefs,
	   dsbcfg_var_t *_vars)
{
	int   i, id;
	bool  error;
	char *var, *val, *p, **pp;
	
	var = str + strspn(str, " \t\r\n");
	if (*var == '\0' || *var == '#')
		return (0);
	for (val = var + strcspn(var, " =\t");
	    *val != '=' && *val != '\0'; val++)
		*val = '\0';
	if (*val != '=') {
		seterr(DSBCFG_ERR_MISSING_SEP, NULL); return (-1);
	}
	*val++ = '\0'; val += strspn(val, " \t\n");
	for (i = 0; i < nvardefs; i++) {
		if (strcmp(var, vardefs[i].name) != 0)
			continue;
		id = vardefs[i].id;
		_vars[id].name = vardefs[i].name;
		_vars[id].type = vardefs[i].type;

		switch (vardefs[i].type) {
		case DSBCFG_VAR_STRINGS:
			for (pp = _vars[id].val.strings;
			     pp != NULL && *pp != NULL; pp++)
				free(*pp), *pp = NULL;
			free(_vars[id].val.strings);
			_vars[id].val.strings = NULL;
			for (p = val; (p = cutok(p, &error)) != NULL;
			     p = NULL) {
				if (add_string(&_vars[id].val.strings, p)
				    == NULL)
					return (-1);
			}
			if (error)
				return (-1);
			break;
		case DSBCFG_VAR_STRING:
			if ((p = cutok(val, &error)) == NULL)
				return (-1);
			free(_vars[id].val.string);
			if ((_vars[id].val.string = strdup(p)) == NULL) {
				seterr(DSBCFG_ERR_SYS_ERROR, "strdup()");
				return (-1);
			}
			break;
		case DSBCFG_VAR_BOOLEAN:
			if ((p = cutok(val, &error)) == NULL)
				return (-1);
			if (strcasecmp(p, "false") == 0 ||
			    strcasecmp(p, "no") == 0	||
			    (isdigit(p[0]) && strtol(p, NULL, 10) == 0))
				_vars[id].val.boolean = false;
			else
				_vars[id].val.boolean = true;
			break;
		case DSBCFG_VAR_INTEGER:
			if ((p = cutok(val, &error)) == NULL)
				return (-1);
			_vars[id].val.integer = strtol(p, NULL, 10);
			break;
		}
		return (0);
	}
	seterr(DSBCFG_ERR_UNKNOWN_VAR, NULL);
	return (-1);
}

static dsbcfg_t *
new_config_node(int nvars)
{
	dsbcfg_t *cp;

	if ((cp = calloc(1, sizeof(dsbcfg_t))) == NULL) {
		seterr(DSBCFG_ERR_SYS_ERROR, "calloc()");
		return (NULL);
	}
	cp->nvars = nvars;
	cp->vars  = calloc(nvars, sizeof(dsbcfg_var_t));
	if (nvars > 0 && cp->vars == NULL) {
		seterr(DSBCFG_ERR_SYS_ERROR, "calloc()");
		return (NULL);
	}
	return (cp);
}

static int
open_cfg_file(const char *subdir, const char *file)
{
	parser.fp     = NULL;
	parser.pbuf   = parser.lnbuf = NULL;
	parser.lineno = parser.bufsz = parser.rd = parser.slen = 0;

	_error.errcode = _error._errno = -1;

	if (cfgpath(subdir, file) == NULL)
		return (-1);
	if ((parser.fp = fopen(parser.file, "r+")) == NULL) {
		seterr(DSBCFG_ERR_SYS_ERROR, parser.file);
		return (-1);
	}
	return (0);
}

static void
close_cfg_file()
{
	if (parser.fp != NULL)
		(void)fclose(parser.fp);
	free(parser.pbuf); free(parser.lnbuf);
	parser.fp     = NULL;
	parser.pbuf   = parser.lnbuf = NULL;
	parser.lineno = parser.bufsz = parser.rd = parser.slen = 0;
}

int
dsbcfg_write(const char *subdir, const char *file, const dsbcfg_t *cfg)
{
	int   i, fd;
	FILE *fp, *tmpfp;
	char *path, tmpl[sizeof(parser.file) + 8];

	fd = -1; fp = tmpfp = NULL; path = NULL;
	if (open_cfg_file(subdir, file) == -1) {
		if (errno != ENOENT)
			goto error;
		if ((path = dsbcfg_mkdir(subdir)) == NULL)
			return (-1);
		free(path);
		if ((path = cfgpath(subdir, file)) == NULL)
			goto error;
		if ((fp = fopen(path, "w+")) == NULL) {
			seterr(DSBCFG_ERR_SYS_ERROR,
			    "Couldn't create config file.");
			goto error;
		}
		(void)fclose(fp);
		if (open_cfg_file(subdir, file) == -1)
			goto error;
	}
	(void)strcpy(tmpl, parser.file); (void)strcat(tmpl, ".XXXXX");

	if ((fd = mkstemp(tmpl)) == -1) {
		seterr(DSBCFG_ERR_SYS_ERROR, "mkstemp()");
		goto error;
	}
	if ((tmpfp = fdopen(fd, "r+")) == NULL) {
		seterr(DSBCFG_ERR_SYS_ERROR, "fdopen()");
		goto error;
	}
	for (; cfg != NULL; cfg = cfg->next) {
		if (cfg->label != NULL)
			(void)fprintf(tmpfp, "%s:\n", cfg->label);
		for (i = 0; i < cfg->nvars; i++)
			write_var(&cfg->vars[i], tmpfp);
		(void)fputs("\n", tmpfp);
	}
	close_cfg_file(); (void)fclose(tmpfp);
	rename(tmpl, parser.file);
	return (0);
error:
	if (tmpfp != NULL)
		(void)fclose(tmpfp);
	free(path); close_cfg_file();
	return (-1);
}

static int
write_var(dsbcfg_var_t *var, FILE *fp)
{
	char *p, **s;

	if (var == NULL)
		return (0);

	switch (var->type) {
	case DSBCFG_VAR_STRING:
		if (var->val.string == NULL)
			return (0);
		if ((p = escape_str(var->val.string)) == NULL)
			return (-1);
		(void)fprintf(fp, "%s = \"%s\"\n", var->name, p);
		free(p);
		break;
	case DSBCFG_VAR_STRINGS:
		(void)fprintf(fp, "%s = ", var->name);
		for (s = var->val.strings;
		    s != NULL && *s != NULL; s++) {
			if ((p = escape_str(*s)) == NULL)
				return (-1);
			(void)fprintf(fp, "\"%s\"", p);
			if (s[1] != NULL)
				(void)fputs(", ", fp);
			free(p);
		}
		(void)fputc('\n', fp);
		break;
	case DSBCFG_VAR_INTEGER:
		(void)fprintf(fp, "%s = %d\n", var->name, var->val.integer);
		break;
	case DSBCFG_VAR_BOOLEAN:
		(void)fprintf(fp, "%s = %s\n", var->name,
		    var->val.boolean ? "true" : "false");
		break;
	}
	return (0);
}

