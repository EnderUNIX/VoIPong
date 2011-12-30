#ifndef RTP_H
#define RTP_H

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


#define PT_ULAW	0
#define PT_G723	4
#define PT_G729	18

#define SNAPLEN	1514
#define MAXNODE	10000

#include <pcap.h>
#include <osspecific.h>

typedef struct rtp_session {
	u_int32_t ip1;
	u_int16_t port1;
	u_int32_t ip2;
	u_int16_t port2;
	char dev[256];
	int rate;
	int size;
	int enc;
	int pid;
	time_t stime;
	struct rtp_session *next;
} rtp_session;

typedef struct rtcp_session rtcp_session;
struct rtcp_session {
	u_int32_t ip1;
	u_int16_t port1;
	u_int32_t ip2;
	u_int16_t port2;
	time_t stime;
	struct rtcp_session *next;
};

struct rtphdr {
	unsigned int cc:4;
	unsigned int ext:1;
	unsigned int pad:1;
	unsigned int ver:2;
	unsigned int pt:7;
	unsigned int mark:1;
	u_int16_t seq;
	u_int32_t timestamp;
	u_int32_t ssrc;
	u_int32_t csrc;
};

typedef struct u_data {
	u_int32_t ip_arr[2];
	int fd[2];
	char ip1[24];
	char ip2[24];
	int dloffset;
	int last_req1;
	int last_req2;
} u_data;

#define	IP_L	sizeof(struct ip)
#define	UDP_L	sizeof(struct udphdr)
#define	RTP_L	sizeof(struct rtphdr)

void removertcp();
void probertp(u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void probertcp(u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet);
int child_loop(pcap_t *pd, int cnt, pcap_handler callback, u_char *user);
unsigned int tuplehash(u_int32_t sip, u_int32_t dip, u_int16_t sp, u_int16_t dp);
void init_voip();
int create_rtp_instance(rtcp_session **, u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet);


#endif
