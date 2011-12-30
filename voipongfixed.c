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



	"Fixed Pcap-Capture-String" Algorithm
	This is useful for catching dummy IP adapters, which has neither signalling 
	nor RTCP, RTSP, but always use fixed port numbers. In voipongnet.conf file, 
	the user is expected to supply a pcap filter string:
	(e.g. "port 40000 and udp").

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
#include <voipongworker.h>
#include <voipongvoip.h>
/*
 * #include <voipongrtcp.h>
 */
#include <voipongnet.h>
#include <miscutil.h>
#include <conf.h>


extern char gdevice[256];
extern char gfilter[1024];
extern int gpromisc;
extern int gsnaplen;
extern int greadtmt;

void
packet_handler_fixed(vnet *v, u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	struct ip *ip;
	struct udphdr *udp;
	short iphlen;
	rtcp_session *rtcp = NULL;

	ip = (struct ip *)packet;
	iphlen = ip->ip_hl << 2;
	if (ip->ip_p != IPPROTO_UDP)
		return;
	udp = (struct udphdr *)(packet + iphlen);
	if (udp->uh_sport == v->fixport || udp->uh_dport == v->fixport) {
		if (worker_isexist(ip->ip_src.s_addr, ip->ip_dst.s_addr, ntohs(udp->uh_sport), ntohs(udp->uh_dport)))
			return;
		if (create_rtp_instance(&rtcp, udata, pkthdr, packet) == -1)
			misc_debug(0, "packet_handler_fixed: failed creating rtp instance\n");
	}
}
