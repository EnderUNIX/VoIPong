
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


#ifndef VOIPONGPCAP_H
#define VOIPONGPCAP_H	1

#define isodd(x)  (x & 1)
#define iseven(x)  !(x & 1)

#include <pcap.h>
#include <voipongnet.h>

typedef struct voipstat voipstat;

struct voipstat {
	double totalpack;
	double rtcppack;
	double rtcpsess;
	double rtpsess;
};

voipstat * getstats();
void setstats(voipstat *s);

int initpcap(int, char *, char *errbuf);
int getdllen();
void peekpcap(int, pcap_handler);
pcap_t *getpcapt();



void packet_handler(u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void packet_handler_lfp(vnet *, u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void packet_handler_lra(vnet *, u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void packet_handler_fixed(vnet *, u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet);


#endif
