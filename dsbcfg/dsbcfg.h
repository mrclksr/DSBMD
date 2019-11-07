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

#ifndef _DSBCFG_H_
#define _DSBCFG_H_

#include <stdbool.h>
#include <sys/types.h>

#define PATH_DSB_CFG_DIR ".config/DSB"

/* Parser error codes. */
#define DSBCFG_ERR_SYNTAX_ERROR (1 << 8)
#define DSBCFG_ERR_INCOMPLETE	(DSBCFG_ERR_SYNTAX_ERROR | 0x01)
#define DSBCFG_ERR_UNTERMINATED (DSBCFG_ERR_SYNTAX_ERROR | 0x02)
#define DSBCFG_ERR_MISSING_SEP  (DSBCFG_ERR_SYNTAX_ERROR | 0x03)
#define DSBCFG_ERR_MISSING_VAL  (DSBCFG_ERR_SYNTAX_ERROR | 0x04)
#define DSBCFG_ERR_UNKNOWN_VAR  (DSBCFG_ERR_SYNTAX_ERROR | 0x05)
#define DSBCFG_ERR_PATH_EXCEED  0x06
#define DSBCFG_ERR_SYS_ERROR	0x07
#define DSBCFG_ERR_DUPLICATED	0x08
	
typedef enum { 
	DSBCFG_VAR_STRING = 1, DSBCFG_VAR_STRINGS, DSBCFG_VAR_INTEGER,
	DSBCFG_VAR_BOOLEAN
} vartype_t;


typedef	union dsbcfg_val_u {
	int  integer;
	bool boolean;
	char *string;
	char **strings;
} dsbcfg_val_t;

/*
 * Struct that defines a config file variable.
 */
typedef struct dsbcfg_var_s {
	char	  *name;
	vartype_t type;	
	dsbcfg_val_t val;
} dsbcfg_var_t;

/*
 * Struct that defines a variable's properties.
 */
typedef struct dsbcfg_vardef_s {
	char	      *name;	/* Variable's name used in config file. */
	vartype_t     type;
	int	      id;	/* Index into a dsbcfg_t's vars array. */	
	dsbcfg_val_t  dflt;	/* Default value. */
} dsbcfg_vardef_t;

/*
 * Struct to hold parsed config file.
 */
typedef struct dsbcfg_s {
	int		nvars;	/* # of variables in 'vars' */
	char		*label;	/* Config file section label. */
	dsbcfg_var_t	*vars;	/* Array of all variables. */
	struct dsbcfg_s	*next;	/* Pointer to next section */
} dsbcfg_t;

#define DSBCFG_VAL(V)		(dsbcfg_val_t)V
#define dsbcfg_getval(CFG, VID)	(CFG->vars[VID].val)
#define dsbcfg_varname(CFG, VID)(CFG->vars[VID].name)
__BEGIN_DECLS
extern int	  dsbcfg_write(const char *, const char *, const dsbcfg_t *);
extern int	  dsbcfg_setval(dsbcfg_t *, int, dsbcfg_val_t);
extern void	  dsbcfg_free(dsbcfg_t *);
extern void	  dsbcfg_printerr(void);
extern void	  dsbcfg_delnode(dsbcfg_t **, const char *);
extern char 	  **dsbcfg_list_to_strings(const char *, bool *);
extern char	  *dsbcfg_mkdir(const char *);
extern dsbcfg_t	  *dsbcfg_new(const char *, dsbcfg_vardef_t *, int);
extern dsbcfg_t	  *dsbcfg_read(const char *, const char *, dsbcfg_vardef_t *,
		   int);
extern dsbcfg_t	  *dsbcfg_getnode(dsbcfg_t *, const char *);
extern dsbcfg_t	  *dsbcfg_addnode(dsbcfg_t *, const char *, dsbcfg_vardef_t *,
		   int);
extern const char *dsbcfg_strerror(void);
__END_DECLS
#endif	/* !_DSBCFG_H_ */

