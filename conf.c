
/*
	VoIPong Voice Over IP Sniffer
	Copyright (C) 2004 Murat Balaban <murat || enderunix.org>

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
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include <conf.h>
#include <miscutil.h>

static const char emptystr[] = "";

int
config_getsectionname(char *sect, int len, char *buf)
{
	int i = 0;
	int j = 0;
	int buflen = strlen(buf);

	memset(sect, 0, len);
	for (buf++, buflen--; j < len - 1 && i < buflen && buf[i] != ']'; i++)
		sect[j++] = buf[i];
	sect[j] = '\0';
	return j;
}

int
config_getkwvalpair(char *kw, int kwlen, char *val, int vallen, char *buf)
{
	int j = 0;
	char *cp1 = NULL;
	int buflen = strlen(buf);

	memset(kw, 0, kwlen);
	memset(val, 0, vallen);
	cp1 = buf;

	for (; !isgraph(*cp1) && (cp1 - buf) < buflen; cp1++)
		;
	for (; *cp1 != '=' && *cp1 != '#' && *cp1 != ' ' && (j < kwlen - 1) && (cp1 - buf) < buflen; cp1++, j++)
		kw[j] = *cp1;
	kw[j] = '\0';
	if (strlen(kw) == 0)
		return 0;
	for (; (!isgraph(*cp1) || *cp1 == '=') && (cp1 - buf) < buflen; cp1++)
		;
	j = 0;
	if (*cp1 == '"')
		for (cp1++; *cp1 != '"' && (j < vallen - 1) && (cp1 - buf) < buflen; cp1++, j++)
			val[j] = *cp1;
	else
		for (; *cp1 != '#' && (j < vallen - 1) && (cp1 - buf) < buflen; cp1++, j++)
			val[j] = *cp1;
	val[j] = '\0';
	if (strlen(val) == 0)
		return 0;
	return 1;
}

config *
config_parse(config *cfg, FILE *fp, char *errbuf)
{
	char kw[KEYWORDSIZ];
	char val[VALSIZ];
	char buf[2048];
	char sect[SECTSIZ];
	int line;
	confsect *sptr = NULL;
	confnode *nptr = NULL;
	confsect *cursect = NULL;

	line = 0;
	while(fgets(buf, sizeof(buf) - 1, fp) != NULL) {
		/* misc_trimnongraph(buf, strlen(buf)); */
		misc_trimnewline(buf, strlen(buf));
		line++;
		if (buf[0] == '#' || strlen(buf) == 0)
			continue;
		if (buf[0] == '[') {
			config_getsectionname(sect, sizeof(sect), buf);
			if ((sptr = (confsect *)calloc(1, sizeof(confsect))) == NULL) {
				config_free(cfg);
				return NULL;
			}
			strncpy(sptr->sect, sect, SECTSIZ - 2);
			sptr->next = cfg->sects;
			cfg->sects = sptr;
			cursect = sptr;
			continue;
		}
		if (!config_getkwvalpair(kw, sizeof(kw), val, sizeof(val), buf))
			continue;
		if (cursect == NULL) {
			if ((sptr = (confsect *)calloc(1, sizeof(confsect))) == NULL) {
				config_free(cfg);
				return NULL;
			}
			strncpy(sptr->sect, "DEFAULT", SECTSIZ - 2);
			sptr->next = cfg->sects;
			cfg->sects = sptr;
			cursect = sptr;
		}
		if ((nptr = (confnode *)calloc(1, sizeof(confnode))) == NULL) {
			config_free(cfg);
			return NULL;
		}
		strncpy(nptr->node, kw, KEYWORDSIZ - 2);
		strncpy(nptr->val, val, VALSIZ - 2);
		nptr->next = cursect->nodes;
		cursect->nodes = nptr;
	}
	fclose(fp);
	return cfg;
}

config *
config_load(config *cfg, const char *path, char *errbuf)
{
	FILE *fp = NULL;

	if ((fp = fopen(path, "r")) == NULL) {
		if (errbuf != NULL)
			snprintf(errbuf, CONFERRBUFSIZ - 2, "config_load: fopen(%s) failed: %s", path, strerror(errno));
		return NULL;
	}
	strncpy(cfg->file, path, CONFFILESIZ - 2);
	cfg->sects = NULL;
	return config_parse(cfg, fp, errbuf);
}

void
config_dump(const config *cfg)
{
	confsect *sect = NULL;
	confnode *node = NULL;

	printf("config_dump for file %s\n\n", cfg->file);
	for (sect = cfg->sects; sect != NULL; sect = sect->next) {
		printf("[%s]\n", sect->sect);
		for (node = sect->nodes; node != NULL; node = node->next)
			printf("\t%s = %s\n", node->node, node->val);
		printf("\n");
	}
}

void
config_free(config *cfg)
{
	confsect *sect = NULL;
	confnode *node = NULL;

	for (sect = cfg->sects; sect != NULL; sect = sect->next) {
		for (node = sect->nodes; node != NULL; node = node->next)
			free(node);
		free(sect);
	}
	cfg->sects = NULL;
}


const char *
config_getval(config *cfg, char *st, char *kw)
{
	confsect *sect = NULL;
	confnode *node = NULL;

	for (sect = cfg->sects; sect != NULL; sect = sect->next) {
		if (st != NULL)
			if (memcmp(sect->sect, st, strlen(sect->sect)) != 0)
				continue;
		for (node = sect->nodes; node != NULL; node = node->next)
			if (memcmp(node->node, kw, strlen(node->node)) == 0)
				return node->val;
		if (st != NULL)
			break;
	}
	return emptystr;
}


int 
config_getstr(config *cfg, char *st, char *kw, char *out, int outlen)
{
	confsect *sect = NULL;
	confnode *node = NULL;
	int cplen = 0;

	for (sect = cfg->sects; sect != NULL; sect = sect->next) {
		if (st != NULL)
			if (memcmp(sect->sect, st, strlen(sect->sect)) != 0)
				continue;
		for (node = sect->nodes; node != NULL; node = node->next)
			if (memcmp(node->node, kw, strlen(node->node)) == 0) {
				cplen = strlen(node->val) < outlen ? strlen(node->val) : outlen - 1;
				memcpy(out, node->val, cplen);
				out[cplen] = '\0';
				return strlen(out);
			}
		if (st != NULL)
			break;
	}
	return 0;
}

int 
config_getint(config *cfg, char *st, char *kw, int defval)
{
	confsect *sect = NULL;
	confnode *node = NULL;

	for (sect = cfg->sects; sect != NULL; sect = sect->next) {
		if (st != NULL)
			if (memcmp(sect->sect, st, strlen(sect->sect)) != 0)
				continue;
		for (node = sect->nodes; node != NULL; node = node->next)
			if (memcmp(node->node, kw, strlen(node->node)) == 0) {
				return atoi(node->val);
			}
		if (st != NULL)
			break;
	}
	return defval;
}


long 
config_getlong(config *cfg, char *st, char *kw, long defval)
{
	confsect *sect = NULL;
	confnode *node = NULL;

	for (sect = cfg->sects; sect != NULL; sect = sect->next) {
		if (st != NULL)
			if (memcmp(sect->sect, st, strlen(sect->sect)) != 0)
				continue;
		for (node = sect->nodes; node != NULL; node = node->next)
			if (memcmp(node->node, kw, strlen(node->node)) == 0) {
				return atol(node->val);
			}
		if (st != NULL)
			break;
	}
	return defval;
}

double 
config_getdouble(config *cfg, char *st, char *kw, double defval)
{
	confsect *sect = NULL;
	confnode *node = NULL;

	for (sect = cfg->sects; sect != NULL; sect = sect->next) {
		if (st != NULL)
			if (memcmp(sect->sect, st, strlen(sect->sect)) != 0)
				continue;
		for (node = sect->nodes; node != NULL; node = node->next)
			if (memcmp(node->node, kw, strlen(node->node)) == 0) {
				return atof(node->val);
			}
		if (st != NULL)
			break;
	}
	return defval;
}


int
config_save(const config *cfg, char *errbuf)
{
	FILE *fp;
	char tstamp[64];
	confsect *sect = NULL;
	confnode *node = NULL;

	if (strlen(cfg->file) == 0) {
		if (errbuf != NULL)
			snprintf(errbuf, CONFERRBUFSIZ - 2, "config_load: cfg->file is not specified!\n");
		return -1;
	}
	if ((fp = fopen(cfg->file, "w")) == NULL) {
		if (errbuf != NULL)
			snprintf(errbuf, CONFERRBUFSIZ - 2, "config_load: fopen(%s) failed: %s", cfg->file, strerror(errno));
		return -1;
	}
	misc_strftime(tstamp, sizeof(tstamp) - 2, "%Y.%m.%d-%H.%M.%S");
	fprintf(fp, "#\n# %s, created by libconfig2 at %s\n#\n\n", cfg->file, tstamp);
	for (sect = cfg->sects; sect != NULL; sect = sect->next) {
		fprintf(fp, "[%s]\n", sect->sect);
		for (node = sect->nodes; node != NULL; node = node->next)
			fprintf(fp, "\t%s=%s\n", node->node, node->val);
		fprintf(fp, "\n");
	}
	fflush(fp);
	fclose(fp);
	return 0;
}
