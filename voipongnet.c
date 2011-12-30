
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
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <ctype.h>
#include <syslog.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#include <voipongsock.h>
#include <voipongpcap.h>
#include <voipongnet.h>

#include <miscutil.h>
#include <conf.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <netinet/in.h>

#include <arpa/inet.h>

vnet *allnets[256];

extern config conf;
extern int pcapfd, mgmtfd;


void
init_vnet()
{
	int i = 0;

	for ( ; i < 256; i++)
		allnets[i] = NULL;
}

void
free_vnet()
{
	int i = 0;
	vnet *v = NULL;

	for (i = 0; i < 256; i++) 
		while ((v = allnets[i]) != NULL) {
			allnets[i] = v->next;
			free(v);
		}
}

void
add_vnet(int ip, int mask, int algo, char *opts)
{
	vnet *v = NULL;
	int h = ip & 0x000000ff; 

	if ((v = malloc(sizeof(vnet))) == NULL) {
		misc_debug(0, "add_vnet: malloc: %s\n", strerror(errno));
		return;
	}
	switch(algo) {
		case ALGORITHM_LRA:
			misc_debug(0, "add_vnet: lra algorithm is not implemented, defaulting to lfp\n");
		case ALGORITHM_LFP:
			v->op = packet_handler_lfp;
			break;
		case ALGORITHM_FIXED:
			v->op = packet_handler_fixed;
			break;
		default:
			v->op = packet_handler_lfp;
			break;
	}
	v->addr = ip;
	v->mask = mask;
	v->fixport = htons(atoi(opts));
	v->next = allnets[h];
	allnets[h] = v;
}

vnet *
get_vnet(int ip)
{
	int h;
	vnet *v;

	h = ip & 0x000000ff; 
	for (v = allnets[h]; v != NULL; v = v->next)
		if ((ip & v->mask) == v->addr)
			return v;
	return NULL;
}

int
loadnetfile(char *netfile)
{
	FILE *fp = NULL;
	char line[1024];
	char strip[24], strmask[24], stralgo[24], stropts[128];
	int i = 0, j = 0, k = 0, buflen = 0, nalgo = 0;

	if ((fp = fopen(netfile, "r")) == NULL) {
		misc_debug(0, "loadnetfile: fopen(%s): %s\n", netfile, strerror(errno));
		return -1;
	}
	while(fgets(line, sizeof(line) - 1, fp) != NULL) {
		k++;
		i = 0, j = 0, buflen = 0;
		memset(strip, 0x0, sizeof(strip));
		memset(strmask, 0x0, sizeof(strmask));
		memset(stralgo, 0x0, sizeof(stralgo));
		memset(stropts, 0x0, sizeof(stropts));
		buflen = strlen(line);
		/* skip white space */
		while(i < buflen && !isgraph(line[i]))
			i++;
		if (line[i] == '#')
			continue;
		while (i < buflen && isgraph(line[i]) && j < sizeof(strip) - 1 && line[i] != '/')
			strip[j++] = line[i++];
		strip[j] = '\0';
		if (strlen(strip) == 0) {
			misc_debug(0, "loadnetfile: parse error at line %d, cannot get ip\n", k);
			continue;
		}
		i++;
		j = 0;
		while (i < buflen && isgraph(line[i]) && j < sizeof(strmask) - 1)
			strmask[j++] = line[i++];
		strmask[j] = '\0';
		if (strlen(strmask) == 0) {
			misc_debug(0, "loadnetfile: parse error at line %d, cannot get mask\n", k);
			continue;
		}
		/* skip white space */
		while(i < buflen && !isgraph(line[i]))
			i++;
		j = 0;
		while (i < buflen && isgraph(line[i]) && j < sizeof(stralgo) - 1)
			stralgo[j++] = line[i++];
		stralgo[j] = '\0';
		if (strlen(stralgo) == 0) {
			misc_debug(0, "loadnetfile: parse error at line %d, cannot get algorithm\n", k);
			continue;
		}
		if (strcmp(stralgo, "fixed") == 0) {
			if (strcmp(strmask, "255.255.255.255") != 0) {
				misc_debug(0, "loadnetfile: fixed algorithm can only by used with hosts, not networks\n");
				continue;
			}
			while(i < buflen && !isgraph(line[i]))
				i++;
			j = 0;
			while (i < buflen && isgraph(line[i]) && j < sizeof(stropts) - 1)
				stropts[j++] = line[i++];
			stropts[j] = '\0';
			if (strlen(stropts) == 0) {
				misc_debug(0, "loadnetfile: parse error at line %d, cannot get port number for fixed algorithm\n", k);
				continue;
			}
		}
		if (strcmp(stralgo, "lfp") == 0)
			nalgo = ALGORITHM_LFP;
		else
		if (strcmp(stralgo, "lra") == 0)
			nalgo = ALGORITHM_LRA;
		else
		if (strcmp(stralgo, "fixed") == 0)
			nalgo = ALGORITHM_FIXED;
		misc_debug(0, "loadnet(%s/%s) method: %s %s\n", strip, strmask, stralgo, stropts);
		add_vnet(inet_addr(strip), inet_addr(strmask), nalgo, stropts);
	}
	fclose(fp);
	return 0;
}
