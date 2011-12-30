#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <pcap.h>

#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>

#include <arpa/inet.h>
#define __USE_BSD 1
#define __FAVOR_BSD 1

#include <netinet/ip.h>
#include <netinet/udp.h>

#include <miscutil.h>

#include <voipong.h>
#include <voipongvoip.h>
#include <voipongworker.h>
#include <voipongpcap.h>

extern char goutdir[256];

struct rtcp_session *rtcps[MAXNODE];

/* !!! Port Numbers are in Host Byte Order !!! */
rtcp_session *
getrtcppair(u_int32_t ip1, u_int16_t port1, u_int32_t ip2, u_int16_t port2)
{
	rtcp_session *rtcp = NULL;
	int h = 0;

	h = tuplehash(ip1, ip2, port1, port2);
	for (rtcp = rtcps[h]; rtcp != NULL; rtcp = rtcp->next) {
		if ((rtcp->ip1 == ip1 || rtcp->ip2 == ip1) && 
				(rtcp->ip2 == ip2 || rtcp->ip1 == ip2) &&
				(rtcp->port1 == port1 || rtcp->port2 == port1) && 
				(rtcp->port2 == port2 || rtcp->port1 == port2))
		return rtcp;
	}
	return NULL;
}

void
removertcp(rtcp_session *in)
{
	rtcp_session *rtcp;
	rtcp_session *prev = NULL;
	int h = 0;

	if (in == NULL)
		return;

	h = tuplehash(in->ip1, in->ip2, in->port1, in->port2);
	for (rtcp = rtcps[h]; rtcp != NULL; rtcp = rtcp->next) {
		if (rtcp->ip1 == in->ip1 && rtcp->ip2 == in->ip2 && rtcp->port1 == in->port1 && rtcp->port2 == in->port2) {
			if (prev == NULL) {
				rtcps[h] = rtcp->next;
				free(rtcp);
				return;
			} else {
				prev->next = rtcp->next;
				free(rtcp);
				return;
			}
		}
		prev = rtcp;
	}
}

/* !!! Port Numbers are in Host Byte Order !!! */
void
checkrtcps(u_int32_t ip1, u_int16_t port1, u_int32_t ip2, u_int16_t port2)
{
	rtcp_session *rtcp = NULL;
	int h = 0;

	h = tuplehash(ip1, ip2, port1, port2);
	for (rtcp = rtcps[h]; rtcp != NULL; rtcp = rtcp->next) {
		if ((rtcp->ip1 == ip1 || rtcp->ip2 == ip1) && 
				(rtcp->ip2 == ip2 || rtcp->ip1 == ip2) &&
				(rtcp->port1 == port1 || rtcp->port2 == port1) && 
				(rtcp->port2 == port2 || rtcp->port1 == port2))
		return;
	}
	rtcp = (rtcp_session *)malloc(sizeof(rtcp_session));
	memset(rtcp, 0x0, sizeof(rtcp_session));
	rtcp->ip1 = ip1;
	rtcp->ip2 = ip2;
	rtcp->port1 = port1;
	rtcp->port2 = port2;
	time(&rtcp->stime);
	rtcp->next = rtcps[h];
	rtcps[h] = rtcp;
}


unsigned int 
tuplehash(u_int32_t sip, u_int32_t dip, u_int16_t sp, u_int16_t dp)
{
	unsigned int key;

	key = (unsigned int)(sip * dip * sp * dp);
	key += ~(key << 15);
	key ^=  (key >> 10);
	key +=  (key << 3);
	key ^=  (key >> 6);
	key += ~(key << 11);
	key ^=  (key >> 16);
	return key % MAXNODE;
}


void
probertcp(u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	struct ip *ip;
	struct udphdr *udp;
        u_char *rtcp;

	ip = (struct ip *)packet;
	udp = (struct udphdr *)(packet + sizeof(struct ip));
	rtcp = (u_char *)(packet + sizeof(struct ip) + sizeof(struct udphdr));

	if (rtcp[0] == 0x80 || rtcp[0] == 0x81)
		if (rtcp[1] == 0xc8 || rtcp[1] == 0xc9)
			checkrtcps(ip->ip_src.s_addr, ntohs(udp->uh_sport), 
					ip->ip_dst.s_addr, ntohs(udp->uh_dport));
}


void
probertp(u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	struct ip *ip;
	struct udphdr *udp;
	rtcp_session *rtcp;

	ip = (struct ip *)packet;
	udp = (struct udphdr *)(packet + sizeof(struct ip));
	
	if (worker_isexist(ip->ip_src.s_addr, ip->ip_dst.s_addr, ntohs(udp->uh_sport), ntohs(udp->uh_dport)))
		return;
	if ((rtcp = getrtcppair(ip->ip_src.s_addr, ntohs(udp->uh_sport) + 1, ip->ip_dst.s_addr, ntohs(udp->uh_dport) + 1)) == NULL)
		return;
	if (create_rtp_instance(&rtcp, udata, pkthdr, packet) == -1)
		misc_debug(0, "failed creating rtp instance\n");
}

int
create_rtp_instance(rtcp_session **rtcp, u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	struct ip *ip;
	struct udphdr *udp;
	struct rtphdr *rtp;
	worker *w;
	u_char *pl;
	int plen = 0;
	int iphlen = 0;

	ip = (struct ip *)packet;
	iphlen = ip->ip_hl << 2;
	udp = (struct udphdr *)(packet + iphlen);
	rtp = (struct rtphdr *)(packet + iphlen + UDP_L);
	pl = (u_char *)(packet + iphlen + UDP_L + RTP_L);
	plen = pkthdr->len - (getdllen() + iphlen + UDP_L + RTP_L);

	if ((w = (worker *)malloc(sizeof(worker))) == NULL) {
		misc_debug(0, "WARNING!!! cannot malloc worker instance: %s\n", strerror(errno));
		return -1;
	}
	w->rtcp = *rtcp;
	if ((w->rtp = (rtp_session *)malloc(sizeof(rtp_session))) == NULL) {
		misc_debug(0, "WARNING!!! cannot malloc rtp_session storage for a worker instance: %s!\n", strerror(errno));
		free(w);
		return -1;
	}
	w->rtp->ip1 = ip->ip_src.s_addr;
	w->rtp->ip2 =  ip->ip_dst.s_addr;
	w->rtp->port1 = ntohs(udp->uh_sport);
	w->rtp->port2 = ntohs(udp->uh_dport);
	time(&w->stime);
	w->rtp->enc = rtp->pt;
	w->next = NULL;
	if (worker_create(&w, plen, pl) == -1) {
		misc_debug(0, "creating worker instance failed\n");
		free(w);
		return -1;
	}
	misc_debug(4, "created a call recorder instance!\n");
	return 0;
}

void
init_voip()
{
	int i = 0;

	for (i = 0; i < MAXNODE; i++)
		rtcps[i] = NULL;
}
