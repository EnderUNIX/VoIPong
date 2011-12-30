#ifndef CONF_H__
#define CONF_H__

/*
	VoIPong Voice Over IP Sniffer
	Copyright (C) 2004 Murat Balaban <murat || enderunix.org>
	All rights reserved.

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version 2
	of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#include <stdio.h>

#define	CONFERRBUFSIZ	1024
#define	CONFFILESIZ	256

#define  SECTSIZ  256
#define  KEYWORDSIZ  256
#define  VALSIZ   1024


typedef struct confsect confsect;
typedef struct confnode confnode;
typedef struct config config;

struct confnode {
	char node[KEYWORDSIZ];
	char val[VALSIZ];
	struct confnode *next;
};

struct confsect {
	char sect[SECTSIZ];
	struct confnode *nodes;
	struct confsect *next;
};

struct config {
	char file[CONFFILESIZ];
	struct confsect *sects;
};

int
config_getsectionname(char *sect, int len, char *buf);

int
config_getkwvalpair(char *kw, int kwlen, char *val, int vallen, char *buf);

config *
config_parse(config *cfg, FILE *fp, char *errbuf);

config *
config_load(config *cfg, const char *path, char *errbuf);

void
config_dump(const config *cfg);

void
config_free(config *cfg);

const char *
config_getval(config *cfg, char *st, char *kw);

int 
config_getstr(config *cfg, char *st, char *kw, char *out, int outlen);

int 
config_getint(config *cfg, char *st, char *kw, int defval);

long 
config_getlong(config *cfg, char *st, char *kw, long defval);

double 
config_getdouble(config *cfg, char *st, char *kw, double defval);

int
config_save(const config *cfg, char *errbuf);


#endif
