
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
#include <syslog.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>

#include <miscutil.h>
#include <conf.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/udp.h>

#include <g711.h>
#include <voipongsign.h>
#include <voipongpcap.h>
#include <voipongmgmt.h>
#include <voipongworker.h>
#include <voipongcdr.h>
#include <voipongcodec.h>

extern char goutdir[256];
extern char gsoxpath[256];
extern char gsoxmixpath[256];
extern int grtp_idle_time;
extern int gsoxmixflag;
extern vocoder vocoders[MAXCODECS];




worker *workers[MAXNODE];
worker *curw = NULL;
pid_t mypid = -1;

static char *rtp_pt_desc[] = {"0-PCMU-8KHz",
	"1-1016-8KHz",
	"2-G726-32-8KHz",
	"3-GSM-8KHz",
	"4-G723.1-8KHz",
	"5-DVI4-8KHz",
	"6-DVI4-16KHz",
	"7-LPC-8KHz",
	"8-PCMA-8KHz",
	"9-G722-8KHz",
	"10-L16-44.1KHz",
	"11-L16-44.1KHz",
	"12-QCELP-8KHz",
	"13-CN-8KHz",
	"14-MPA-90KHz",
	"15-G728-8KHz",
	"16-DVI4-11KHz",
	"17-DVI4-22KHz",
	"18-G729-8KHz",
	"19-reserved",
	"20-unassigned",
	"21-unassigned",
	"22-unassigned",
	"23-unassigned",
	"24-unassigned",
	"25-CelB-90KHz",
	"26-JPEG-90KHz",
	"27-unassigned"
};

int
create_wave()
{
	char outf1[1024];
	char outf2[1024];
	char mixout[1024];
	char inrate[32];
	char insize[4];
	char indenc[4];
	struct stat st;
	int outcnt = 0;
	

	if (vocoders[curw->rtp->enc].f == vocoder_default) {
		misc_debug(0, "[%d] create_wave: no modules have been loaded to decode payload type: %d\n", getpid(), curw->rtp->enc);
		misc_debug(0, "[%d] create_wave: leaving *.raw files untouched.\n", getpid());
		return -1;
	}
	snprintf(inrate, sizeof(inrate) - 1, "%d", vocoders[curw->rtp->enc].rate);
	strcpy(insize, "-w");
	strcpy(indenc, "-s");

	strncpy(outf1, curw->file1name, sizeof(outf1) - 2);
	memcpy(outf1 + (strlen(outf1) - 4), ".wav", 4);
	if (stat(curw->file1name, &st) == 0) {
		if (exec_sox(inrate, insize, indenc, curw->file1name, outf1) == 0) {
			if (unlink(curw->file1name) == -1)
				misc_debug(0, "[%d] Cannot remove file [%s]: %s\n", mypid, curw->file1name, strerror(errno));
		} else {
			misc_debug(0, "[%d] exec_sox failed!\n", mypid);
			return -1;
		}
		misc_debug(0, "[%d] .WAV file %s has been created successfully\n", mypid, outf1);
		outcnt++;
	}

	strncpy(outf2, curw->file2name, sizeof(outf2) - 2);
	memcpy(outf2 + (strlen(outf2) - 4), ".wav", 4);
	if (stat(curw->file2name, &st) == 0) {
		if (exec_sox(inrate, insize, indenc, curw->file2name, outf2) == 0) {
			if (unlink(curw->file2name) == -1)
				misc_debug(0, "[%d] Cannot remove file [%s]: %s\n", mypid, curw->file2name, strerror(errno));
		} else {
			misc_debug(0, "[%d] exec_sox failed!\n", mypid);
			return -1;
		}
		misc_debug(0, "[%d] .WAV file %s has been created successfully\n", mypid, outf2);
		outcnt++;
	}
	if (gsoxmixflag && (outcnt > 1)) {
 		strncpy(mixout, curw->file1name, sizeof(mixout) - 13);
  		strcpy(mixout + (strlen(mixout) - 4), "-mixed.wav");	
  		if (exec_soxmix(outf1, outf2, mixout) == 0) {
  			misc_debug(0, "[%d] Mixed output files: %s\n", mypid, mixout);
			/*
  			if(unlink(outf1) == -1)
  				misc_debug(0, "[%d] Cannot remove file [%s]: %s\n", mypid, outf1, strerror(errno));
  			if(unlink(outf2) == -1)
  				misc_debug(0, "[%d] Cannot remove file [%s]: %s\n", mypid, outf2, strerror(errno));		
				*/
  		} else {
  			misc_debug(0, "[%d] Could not mix output files: exec_soxmix failed!\n", mypid);
  		}
		
	}
	return 0;
}

int
exec_sox(char *rt, char *sz, char *dc, char *srcfile, char *dstfile)
{
	pid_t pid, wpid;
	int stat = 0;
	int exitcode = 0;

	switch(pid = fork())  {
		case -1:
			misc_debug(0, "[%d] exec_sox: cannot fork new process to create .WAV file: %s\n", mypid, strerror(errno));
			return -1;
			break;
		case 0:
			if (execl(gsoxpath, "sox", "-r", rt, sz, dc, srcfile, dstfile, NULL) == -1) {
				misc_debug(0, "[%d] execl(%s -r %s %s %s %s %s) error: %s\n", mypid, gsoxpath, rt, sz, dc, srcfile, dstfile, strerror(errno));
				exit(100);
			}
			exit(1);
			break;
		default:
			if ((wpid = waitpid(pid, &stat, 0)) == -1) {
				misc_debug(0, "[%d] exec_sox: waitpid: %s\n", mypid, strerror(errno));
				return -1;
			}
			if ((exitcode = WEXITSTATUS(stat)) != 0) {
				misc_debug(0, "[%d] exec_sox: sox helper process failed, return value: %d\n", mypid, exitcode);
				return -1;
			} else
			if (WIFSIGNALED(stat)) {
				misc_debug(0, "[%d] exec_sox: sox helper process recv'd siganal %d\n", mypid, pid, WTERMSIG(stat));
				return -1;
			}
			break;
	}
	return 0;
}

int
exec_soxmix(char *f1, char *f2, char *dstfile)
{
	pid_t pid, wpid;
	int stat = 0;
	int exitcode = 0;

	switch(pid = fork())  {
		case -1:
			misc_debug(0, "[%d] exec_soxmix: cannot fork new process to create mixed .WAV file: %s\n", mypid, strerror(errno));
			return -1;
			break;
		case 0:
			if (execl(gsoxmixpath, "soxmix", f1, f2, dstfile, NULL) == -1) {
				misc_debug(0, "[%d] execl(%s %s %s %s) error: %s\n", mypid, gsoxmixpath, f1, f2, dstfile, strerror(errno));
				exit(100);
			}
			exit(1);
			break;
		default:
			if ((wpid = waitpid(pid, &stat, 0)) == -1) {
				misc_debug(0, "[%d] exec_soxmix: waitpid: %s\n", mypid, strerror(errno));
				return -1;
			}
			if ((exitcode = WEXITSTATUS(stat)) != 0) {
				misc_debug(0, "[%d] exec_soxmix: soxmix helper process failed, return value: %d\n", mypid, exitcode);
				return -1;
			} else
			if (WIFSIGNALED(stat)) {
				misc_debug(0, "[%d] exec_soxmix: soxmix helper process recv'd siganal %d\n", mypid, pid, WTERMSIG(stat));
				return -1;
			}
			break;
	}
	return 0;
}





void
init_workers()
{
	int i = 0;

	for (i = 0; i < MAXNODE; i++)
		workers[i] = NULL;
}

int
worker_create(worker **w, int pllen, u_char *packet)
{
	int h = 0;

	switch(((*w)->pid = fork())) {
		case -1:
			misc_debug(0, "worker_create: fork: %s\n", strerror(errno));
			break;
		case 0:
			worker_main(*w, pllen, packet);
			exit(0);
		default:
			time(&(*w)->rtp->stime);
			h = tuplehash((*w)->rtp->ip1, (*w)->rtp->ip2, (*w)->rtp->port1, (*w)->rtp->port2);
			(*w)->next = workers[h];
			workers[h] = (*w);
			break;
	}
	return (*w)->pid;
}

worker *
getworkerbypid(pid_t pid)
{
	worker *w;
	int i;

	for (i = 0; i < MAXNODE; i++)
		for (w = workers[i]; w != NULL; w = w->next)
			if (w->pid == pid)
				return w;

	return NULL;
}

int
worker_isexist(u_int32_t ip1, u_int32_t ip2, u_int16_t port1, u_int16_t port2)
{
	worker *w;
	int h;

	h = tuplehash(ip1, ip2, port1, port2);
	for (w = workers[h]; w != NULL; w = w->next)
		if ((ip1 == w->rtp->ip1 || ip1 == w->rtp->ip2) &&
				(ip2 == w->rtp->ip1 || ip2 == w->rtp->ip2) &&
				(port1 == w->rtp->port1 || port1 == w->rtp->port2) &&
				(port2 == w->rtp->port1 || port2 == w->rtp->port2))
			return 1;
	return 0;
}

void
worker_remove(worker *in)
{
	worker *w;
	worker *prev = NULL;
	int h = 0;

	/* Remove related RTCP session */
	removertcp(in->rtcp);

	h = tuplehash(in->rtp->ip1, in->rtp->ip2, in->rtp->port1, in->rtp->port2);
	for (w = workers[h]; w != NULL; w = w->next) {
		if (in->pid == w->pid) {
			if (prev == NULL)
				workers[h] = w->next;
			else
				prev->next = w->next;
		}
		prev = w;
	}
}

void
kill_workers()
{
	worker *w = NULL;
	int i = 0;

	for (i = 0; i < MAXNODE; i++)
		for (w = workers[i]; w != NULL; w = w->next)
			if (w->pid > 1) {
				misc_debug(0, "Terminating session [%d]\n", w->pid);
				kill(w->pid, SIGTERM);
			}
}

void
worker_main(worker *w, int pllen, u_char *payload)
{
	char filterstr[512];
	char errbuf[ERRBUFSIZ];
	char strpt[32];
	char tfmt[64];
	char strip1[32];
	char strip2[32];
	int pd = -1;
	pcap_t *pcapptr;
	fd_set set;
	time_t tnow, tidle;
	struct timeval tv;
	struct sigaction sa, sa1;
	struct sigaction sa_old, sa_old1;

	sa.sa_handler = sigworkerhandler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGHUP, &sa, &sa_old);
	sigaction(SIGUSR2, &sa, &sa_old);
	sigaction(SIGTERM, &sa, &sa_old);
	sigaction(SIGINT, &sa, &sa_old);
	sigaction(SIGSTOP, &sa, &sa_old);
	sigaction(SIGQUIT, &sa, &sa_old);
	sigaction(SIGALRM, &sa, &sa_old);
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa1.sa_mask);
	sigaction(SIGCHLD, &sa1, &sa_old1);

	curw = w;
	mypid = getpid();
	misc_strftime(tfmt, sizeof(tfmt) - 2, "%Y%m%d");
	snprintf(strip1, sizeof(strip1) - 2, misc_inet_ntoa(w->rtp->ip1));
	snprintf(strip2, sizeof(strip2) - 2, misc_inet_ntoa(w->rtp->ip2));
	if (create_outpath() == -1) {
		misc_debug(0, "[%d] create_path failed!\n", mypid);
		exit(1);
	}
	if (w->rtp->enc > MAXCODECS) {
		misc_debug(0, "Encoding type %d is higher than MAXCODECS value [%d], giving up...\n", w->rtp->enc, MAXCODECS);
		exit(0);
	}
	if (w->rtp->enc > 27)
		snprintf(strpt, sizeof(strpt) - 2, "%d-unknown", w->rtp->enc);
	else
		snprintf(strpt, sizeof(strpt), "%s", rtp_pt_desc[w->rtp->enc]);

	snprintf(w->file1name, MAXLBUFSIZ - 2, "%s/%s/session-enc%s-%s,%d-%s,%d.raw", goutdir, tfmt, strpt, 
			strip1, w->rtp->port1, strip2, w->rtp->port2);
	if ((w->ip1fd = creat(w->file1name, S_IRWXU)) == -1) {
		misc_debug(0, "[%d] Cannot create raw voice output file %s: %s\n", mypid, w->file1name, strerror(errno));
		exit(1);
	}
	snprintf(w->file2name, MAXLBUFSIZ - 2, "%s/%s/session-enc%s-%s,%d-%s,%d.raw", goutdir, tfmt, strpt, 
			strip2, w->rtp->port2, strip1, w->rtp->port1);
	if ((w->ip2fd = creat(w->file2name, S_IRWXU)) == -1) {
		misc_debug(0, "[%d] Cannot create raw voice output file %s: %s\n", mypid, w->file2name, strerror(errno));
		exit(1);
	}
	switch(w->rtp->enc) {
		case PT_ULAW:
			w->rtp->rate = 8000;
			break;
		default:
			w->rtp->rate = 0;
			break;
	}
	misc_debug(0, "[%d] VoIP call has been detected.\n", mypid);
	misc_debug(0, "[%d] %s:%d <--> %s:%d\n", mypid, strip1, w->rtp->port1, strip2, w->rtp->port2);
	misc_debug(0, "[%d] Encoding %s, recording.......\n", mypid, strpt);

	/* Now, let's talk real bussiness ! */
	/* First RTP packet, inherited from parent process */
	vocoders[curw->rtp->enc].f (w->ip1fd, payload, pllen);

	/* Reopen pcap interface for a fixed port tuple ! */
	snprintf(filterstr, sizeof(filterstr) - 2, "(host %s and port %d) and (host %s and port %d) and udp",
			strip1, w->rtp->port1, strip2, w->rtp->port2);
	if ((pd = initpcap(0, filterstr, errbuf)) == -1) {
		misc_debug(0, "[%d] initpcap: %s\n", mypid, errbuf);
		exit(1);
	}
	pcapptr = getpcapt();

	tv.tv_sec = grtp_idle_time;
	tv.tv_usec = 0;
	time(&tnow);
	tidle = tnow;
	for ( ; ; ) {
		FD_ZERO(&set);
		FD_SET(pd, &set);
		switch(select(pd + 1, &set, NULL, NULL, &tv)) {
			case -1:
				misc_debug(0, "[%d] select: error: %s\n", mypid, strerror(errno));
				exit(1);
				break;
			case 0:
				time(&tnow);
				if ((tnow - tidle) > grtp_idle_time) {
					misc_debug(0, "[%d] maximum idle time [%d secs] has been elapsed for this call, the call might have been ended.\n", mypid,
							grtp_idle_time);
					w->etime = time(&w->etime) - grtp_idle_time;
					if (create_wave() == 0) {
						unlink(curw->file1name);
						unlink(curw->file2name);
					}
					worker_graceful_exit(0);
				}
				break;
			default:
				time(&tidle);
				peekpcap(-1, dumprtppayload);
				break;
		}
	}
	exit(0);
}

void
dumprtppayload(u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	u_char *pl;
	int plen = 0;
	struct ip *ip;
	int fd = -1;
	int off = 0;
	int iphlen = 0;
	unsigned short padlen = 0;
	struct rtphdr *rtp;
	unsigned short cur_seq = 0;
	static unsigned short last_seq1 = 0, last_seq2 = 0;

	off = getdllen();
	ip = (struct ip *)(packet + off);
	iphlen = ip->ip_hl << 2;
	rtp = (struct rtphdr *)(packet + off + iphlen + UDP_L);
	pl = (u_char *)(packet + off + iphlen + UDP_L + RTP_L);
	plen = pkthdr->len - (getdllen() + iphlen + UDP_L + RTP_L);
	if (rtp->pad) { /* If padding is enabled, calc real payload length */
		padlen = (unsigned short)(pl[plen]);
		plen -= padlen;
	}
	/*
	printf("\n[-------- START RTP HEADER ----------]\n");
	printf("Version   : %d\n", rtp->ver);
	printf("Padding   : %d\n", rtp->pad);
	printf("Extension : %d\n", rtp->ext);
	printf("CSRC count: %d\n", rtp->cc);
	printf("Mark      : %d\n", rtp->mark);
	printf("Payload   : %d\n", rtp->pt);
	printf("SeqNo     : %d\n", rtp->seq);
	printf("Timestamp : %d\n", rtp->timestamp);
	printf("SSRC      : %d\n", rtp->ssrc);
	printf("CSRC      : %d\n", rtp->csrc);
	printf("[---------- END RTP HEADER ----------]\n");
	*/
	/* Avoid duplicate packets */
	cur_seq = ntohs(rtp->seq);
	if (cur_seq == last_seq1 || cur_seq == last_seq2)
		return;
	if (ip->ip_src.s_addr == curw->rtp->ip1) {
		fd = curw->ip1fd;
		last_seq1 = cur_seq;
	} else {
		fd = curw->ip2fd;
		last_seq2 = cur_seq;
	}
	vocoders[curw->rtp->enc].f (fd, pl, plen);
}

int
create_outpath()
{
	char tfmt[64];
	char filefmt[512];
	struct stat st;

	if (stat(goutdir, &st) == -1)
		if (errno == ENOENT) {
			if (mkdir(goutdir, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0) {
				misc_debug(0, "cannot create outputdir %s: %s\n", goutdir, strerror(errno));
				return -1;
			}
		}

	misc_strftime(tfmt, sizeof(tfmt) - 1, "%Y%m%d");
	snprintf(filefmt, sizeof(filefmt) - 2, "%s/%s", goutdir, tfmt);

	if (stat(filefmt, &st) == -1)
		if (errno == ENOENT) {
			if (mkdir(filefmt, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0) {
				misc_debug(0, "cannot create daily outputdir %s: %s\n", filefmt, strerror(errno));
				return -1;
			}
		}
	return 0;
}

void
worker_graceful_exit(int code)
{
	if (code == 0) 
		add2cdr(curw);
	exit(code);
}
