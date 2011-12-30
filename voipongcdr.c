#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#include <pcap.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
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
extern char gcdrfile[256];

void
checkcdrfile()
{
	struct stat st;
	FILE *fp;

	if (stat(gcdrfile, &st) == -1)
		if (errno == ENOENT) {
			if ((fp = fopen(gcdrfile, "a")) == NULL) {
				misc_debug(0, "checkcdrfile: fopen(%s): %s\n", gcdrfile, strerror(errno));
				return;
			}
			writew_lock(fileno(fp));
			fprintf(fp, "Start;End;Duration(seconds);Session Id;Party1 RTP Pair; Party 2 RTP Pair;Encoding;Rate\n");
			fclose(fp);
		}
}

int
add2cdr(worker *w)
{
	FILE *fp;
	char stime[256];
	char etime[256];

	checkcdrfile();
	if ((fp = fopen(gcdrfile, "a")) == NULL) {
		misc_debug(0, "add2cdr: fopen(%s): %s\n", gcdrfile, strerror(errno));
		return -1;
	}
	writew_lock(fileno(fp));
	misc_strftimegiven(stime, sizeof(stime) - 2, "%a %b %d %H:%M:%S %Y", w->stime);
	misc_strftimegiven(etime, sizeof(etime) - 2, "%a %b %d %H:%M:%S %Y", w->etime);

	fprintf(fp, "%s;%s;%d;%d;%s:%d;%s:%d;%d;%d\n", stime, etime, (w->etime - w->stime), getpid(), 
			misc_inet_ntoa(w->rtp->ip1), w->rtp->port1,
			misc_inet_ntoa(w->rtp->ip2), w->rtp->port2, w->rtp->enc, w->rtp->rate);
	fclose(fp);
	return 0;
}
