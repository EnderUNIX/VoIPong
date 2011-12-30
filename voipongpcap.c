
/*
	VoIPong Voice Over IP Sniffer
	Copyright (C) 2005 Murat Balaban <murat || enderunix.org>
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <pcap.h>

#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define __USE_BSD 1
#define __FAVOR_BSD 1

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <voipong.h>
#include <voipongsock.h>
#include <voipongpcap.h>
#include <voipongvoip.h>
/*
 * #include <voipongrtcp.h>
 */
#include <voipongnet.h>
#include <miscutil.h>
#include <conf.h>

#define	MINPACKETSIZ	(getdllen() + sizeof(struct ip) + sizeof(struct udphdr) + 20)


static pcap_t *pd = NULL;
static int dllen = 14;
static voipstat stats;

extern char gdevice[256];
extern char gfilter[1024];
extern int gpromisc;
extern int gsnaplen;
extern int greadtmt;

extern void (*packet_handler_default) (vnet *, u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet);


pcap_t *
getpcapt()
{
	return pd;
}

voipstat *
getstats()
{
	return &stats;
}

void
setstats(voipstat *s)
{
	memcpy(&stats, s, sizeof(voipstat));
}

int
initpcap(int verbose, char *filter, char *errbuf)
{
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	char netstr[64], maskstr[64];
	struct bpf_program fprog;
	struct in_addr in;
	char *dev;
	char perrbuf[PCAP_ERRBUF_SIZE];

	if (strlen(gdevice) == 0) {
		if ((dev = pcap_lookupdev(perrbuf)) == NULL) {
			snprintf(errbuf, ERRBUFSIZ - 2, "cannot find any available device to sniff on: %s\n", perrbuf);
			return -1;
		}
		strncpy(gdevice, dev, sizeof(gdevice) - 2);
	}
	if ((pd = pcap_open_live(gdevice, gsnaplen, gpromisc, greadtmt, perrbuf)) == NULL) {
		snprintf(errbuf, ERRBUFSIZ - 2, "pcap_open_live: %s\n", perrbuf);
		return -1;
	}

	pcap_lookupnet(gdevice, &netp, &maskp, perrbuf);
	in.s_addr = netp;
	strncpy(netstr, inet_ntoa(in), sizeof(netstr) - 2);
	in.s_addr = maskp;
	strncpy(maskstr, inet_ntoa(in), sizeof(maskstr) - 2);

	switch(pcap_datalink(pd)) {
		case DLT_EN10MB:
			dllen = 14;
			break;
		case DLT_IEEE802:
			dllen = 22;
			break;
		case DLT_FDDI:
			dllen = 21;
			break;
		case DLT_PPP:
			dllen = 12;
			break;
		case DLT_NULL:
			dllen = 4;
			break;
	}
	if (verbose)
		misc_debug(0, "%s has been opened in  %s mode. (%s/%s)\n", gdevice, (gpromisc ? "promisc" : "non-promisc"), netstr, maskstr);
	if (strlen(filter) > 0) {
		pcap_compile(pd, &fprog, filter, 0, netp);
		pcap_setfilter(pd, &fprog);
		pcap_freecode(&fprog);
		if (pcap_setnonblock(pd, 1, perrbuf) == -1) {
			misc_debug(0, "pcap_setnonblock: %s\n", perrbuf);
			wexit(1);
		}
	}
	return pcap_fileno(pd);
}

void
peekpcap(int cnt, pcap_handler phandler)
{
	while (pcap_dispatch(pd, cnt, phandler, (u_char *)dllen) != 0)
		;
}

int
getdllen()
{
	return dllen;
}

void
packet_handler(u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	int offset = (int)udata;
	struct ip *ip;
	struct udphdr *udp;
	vnet *v;

	if (pkthdr->len < MINPACKETSIZ)
		return;

	ip = (struct ip *)(packet + offset);
	if (ip->ip_p == IPPROTO_UDP) {
		udp = (struct udphdr *)(packet + offset + sizeof(struct ip));
		if (ntohs(udp->uh_sport) < 5000 || ntohs(udp->uh_dport) < 5000)
			return;
	}
	if ((v = get_vnet(ip->ip_src.s_addr)) == NULL)
		if ((v = get_vnet(ip->ip_dst.s_addr)) == NULL) {
			(packet_handler_default) (NULL, udata, pkthdr, (const u_char *)ip);
			return;
		}
	(v->op) (v, udata, pkthdr, (const u_char *)ip);
}

/* "Least Run-Away"  Algorithm
 *
 * This *new* one has been designed to catch calls, impossible to catch with the default
 * algorithm, which tries to minimize false positives.
 *
 * So, if your network routes non RFC-compliant calls, and you cannot catch them with L.F.P,
 * you should give this a try.
 *
 */
void
packet_handler_lra(vnet *v, u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	misc_debug(0, "! lra not implemented yet !\n");
}
