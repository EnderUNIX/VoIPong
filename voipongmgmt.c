
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
#include <pwd.h>
#include <fcntl.h>

#include <miscutil.h>
#include <conf.h>
#include <voipongmgmt.h>
#include <voipong.h>
#include <voipongsock.h>
#include <voipongvoip.h>
#include <voipongworker.h>
#include <voipongnet.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/param.h>

#include <netinet/in.h>

extern config cfg;
extern int gdbg;
extern time_t gstarttime;
extern int gsoxmixflag;
extern char gcfgfile[];
extern char gnetfile[];
extern rtp_session *rtps;
extern worker *workers[MAXNODE];
extern rtcp_session *rtcps[MAXNODE];

static int mgmtfd = -1;
static int mgmtconnected = 0;
static int authok = 0;
static int passtries = 0;
static FILE *fp;

static void 
uptime()
{
	char str[512];

	fprintf(fp, "+OK %s\n", misc_getuptimestr(str, sizeof(str) - 1, gstarttime));
}

static void 
loadnets()
{
	free_vnet();
	if (loadnetfile(gnetfile) != 0) {
		fprintf(fp, "-ERR cannot load voipongnets file!\n");
		misc_debug(0, "mgmt: loadnets: cannot load voipongnets file!\n");
		return;
	}
	fprintf(fp, "+OK networks file has been reloaded.\n");
}



static void
killcall(char *line)
{
	char sid[128];
	int nsid;

	if (strlen(line) < 9)
		return;
	strncpy(sid, line + 9, sizeof(sid) - 2);
	if ((nsid = atoi(sid)) < 2) {
		fprintf(fp, "+ERR Invalid session ID: %d\n", nsid);
		return;
	}
	if (getworkerbypid(nsid) == NULL) {
		fprintf(fp, "+ERR No such session by ID: %d\n", nsid);
		return;
	}
	kill(nsid, SIGTERM);
	fprintf(fp, "+OK Sent deadly signal to session %d\n", nsid);
}

static void
setdebug(char *line)
{
	char dl[128];
	int ndl;

	if (strlen(line) < 9)
		return;
	strncpy(dl, line + 9, sizeof(dl) - 2);
	if ((ndl = atoi(dl)) < 0 || ndl > 4) {
		fprintf(fp, "+ERR Invalid debug level: %d, valid levels are 0 through 4\n", ndl);
		return;
	}
	gdbg = ndl;
	misc_setloglevel(ndl);
	fprintf(fp, "+OK set new debug level to %d\n", ndl);
	misc_debug(0, "mgmt_console: set new debug level to %d\n", ndl);
}

static void
setmixflag(char *line)
{
	char dl[128];
	int ndl;

	if (strlen(line) < 10)
		return;
	strncpy(dl, line + 10, sizeof(dl) - 2);
	ndl = atoi(dl);
	gsoxmixflag = (ndl ? 1 : 0);
	fprintf(fp, "+OK set mixflag to %d\n", ndl);
	misc_debug(0, "mgmt_console: set mixflag to %d\n", gsoxmixflag);
}



static void
shrtcp()
{
	int i = 0;
	char tstr[64];
	char ipstr1[32];
	char ipstr2[32];
	time_t now;
	rtcp_session *w;
	int j = 0;

	fprintf(fp, "+OK +\n");
	fprintf(fp, "\n\n");
	fprintf(fp, "%-5.5s %-16.16s %s %-16.16s %s %-17.17s\n", "ID", "NODE1", "PORT1", "NODE2", "PORT2", "STIME");
	fprintf(fp, "----- ---------------- ----- ---------------- ----- -----------------\n");

	time(&now);
	for (i = 0; i < MAXNODE; i++) {
		for (w = rtcps[i]; w != NULL; w = w->next, i++) {
			j++;
			misc_strftimegiven(tstr, sizeof(tstr) - 2, "%d/%m/%y %H:%M:%S", w->stime);
			snprintf(ipstr1, sizeof(ipstr1) - 2, "%s", misc_inet_ntoa(w->ip1));
			snprintf(ipstr2, sizeof(ipstr2) - 2, "%s", misc_inet_ntoa(w->ip2));
			fprintf(fp, "%05d %-16.16s %05d %-16.16s %05d %-17.17s\n", j, ipstr1, w->port1,
					ipstr2, w->port2,
					tstr);
		}
	}
	fprintf(fp, "\n");
	fprintf(fp, "Total listed: %d\n", j);
	fprintf(fp, "+OK .\n");
	fflush(fp);
}

static void
shcall()
{
	int i = 0;
	char tstr[64];
	char ipstr1[32];
	char ipstr2[32];
	time_t now;
	worker *w;
	int j = 0;

	fprintf(fp, "+OK +\n");
	fprintf(fp, "\n\n");
	fprintf(fp, "%-5.5s %-16.16s %s %-16.16s %s %-17.17s %-12.12s\n", "ID", "NODE1", "PORT1", "NODE2", "PORT2", "STIME", "DURATION");
	fprintf(fp, "----- ---------------- ----- ---------------- ----- ----------------- ------------\n");

	time(&now);
	for (i = 0; i < MAXNODE; i++) {
		for (w = workers[i]; w != NULL; w = w->next, i++) {
			j++;
			misc_strftimegiven(tstr, sizeof(tstr) - 2, "%d/%m/%y %H:%M:%S", w->rtp->stime);
			snprintf(ipstr1, sizeof(ipstr1) - 2, "%s", misc_inet_ntoa(w->rtp->ip1));
			snprintf(ipstr2, sizeof(ipstr2) - 2, "%s", misc_inet_ntoa(w->rtp->ip2));
			fprintf(fp, "%05d %-16.16s %05d %-16.16s %05d %-17.17s %d seconds\n", w->pid, ipstr1, w->rtp->port1,
					ipstr2, w->rtp->port2,
					tstr, (now - (int)w->rtp->stime)
					);
		}
	}
	fprintf(fp, "\n");
	fprintf(fp, "Total listed: %d\n", j);
	fprintf(fp, "+OK .\n");
	fflush(fp);
}

static void 
info()
{
	struct passwd *pwd;
	char tmp[512];

	fprintf(fp, "+OK +\n");
	fprintf(fp, "General Server Info:\n");
	fprintf(fp, "--------------------------:\n");
	fprintf(fp, "Server version            : %s\n", VERSION);
	fprintf(fp, "System                    : %s\n", misc_getunamestr(tmp, sizeof(tmp) - 2));
	getcwd(tmp, sizeof(tmp) - 2);
	fprintf(fp, "Current work. direct.     : %s\n", tmp);
	fprintf(fp, "Log level                 : %d\n", gdbg);
	fprintf(fp, "Mix Voice Flag            : %s\n", (gsoxmixflag ? "true" : "false"));
	fprintf(fp, "Process ID (PID)          : %d\n", getpid());
	pwd = getpwuid(getuid());
	fprintf(fp, "User                      : %s [%s]\n", pwd->pw_name, pwd->pw_gecos);
	fprintf(fp, "Group                     : %d\n", pwd->pw_gid);

	fprintf(fp, "+OK .\n");
	fflush(fp);
}

int 
rusage()
{
	struct rusage ru;

	if (getrusage(RUSAGE_SELF, &ru) < 0) {
		misc_debug(0, "mgmt_console: rusage error : %s\n", strerror(errno));
		fprintf(fp, "+ERR mgmt_console: rusage error : %s\n", strerror(errno));
		return -1;
	}

	fprintf(fp, "+OK +\n");
	fprintf(fp, "Current CPU usage stats:\n");
	fprintf(fp, "----------------------------------------\n");
	fprintf(fp, "Total  \"user\" time                    : %ld seconds\n", ru.ru_utime.tv_sec);
	fprintf(fp, "Total used \"system\" time              : %ld seconds\n", ru.ru_stime.tv_sec);
	fprintf(fp, "Shared Memory Size                    : %ld KB\n", ru.ru_ixrss);
	fprintf(fp, "Integral Memory Size                  : %ld KB\n", ru.ru_idrss);
	fprintf(fp, "Integral stack Size                   : %ld KB\n", ru.ru_isrss);
	fprintf(fp, "Page requests                         : %ld\n", ru.ru_minflt);
	fprintf(fp, "Page errors                           : %ld\n", ru.ru_majflt);
	fprintf(fp, "Block input operations                : %ld\n", ru.ru_inblock);
	fprintf(fp, "Block output operations               : %ld\n", ru.ru_oublock);
	fprintf(fp, "Messages sent                         : %ld\n", ru.ru_msgsnd);
	fprintf(fp, "Messages received                     : %ld\n", ru.ru_msgrcv);
	fprintf(fp, "Signals                               : %ld\n", ru.ru_nsignals);
	fprintf(fp, "Voluntary \"context switch\"s           : %ld\n", ru.ru_nvcsw);
	fprintf(fp, "Involuntary \"context switch\"s         : %ld\n", ru.ru_nivcsw);

	fprintf(fp, "+OK .\n");
	fflush(fp);

	return 0;

}

int 
is_mgmt_active()
{
	return mgmtconnected;
}

int 
get_mgmt_fd()
{
	return mgmtfd;
}

void 
accept_mgmt_client(int fd)
{
	struct sockaddr_in cin;
	size_t len;
	int nsd;
	int flags;
	char tmp[512];

	len = sizeof(cin);
	memset(&cin, 0, sizeof(cin));
	if ((nsd = accept(fd, (void *)&cin, &len)) < 0) {
		misc_debug(0, "accept_mgmt_client: accept error: %s\n", strerror(errno));
		return;
	}
	flags = fcntl(nsd, F_GETFL, 0);
	fcntl(nsd, F_SETFL, flags | O_NONBLOCK);
	if (is_mgmt_active() == 1)
		close_mgmt_client();

	misc_debug(0, "New management console request has been accepted!\n");
	if ((fp = fdopen(nsd, "r+")) == NULL) {
		misc_debug(0, "MGMT: fdopen: %s\n", strerror(errno));
		return;
	}
	mgmtconnected = 1;
	mgmtfd = nsd;
	add_to_select_set(mgmtfd);
	misc_getunamestr(tmp, sizeof(tmp) - 2);
	fprintf(fp, "+OK %s\r\n", tmp);
	fflush(fp);
}

void 
process_mgmt_request()
{
	char line[1024];


	if ((fgets(line, sizeof(line) - 2, fp)) == NULL) {
		misc_debug(0, "process_mgmt_read: fgets error: %s\n", strerror(errno));
		close_mgmt_client();
		return;
	}
	misc_trimnewline(line, strlen(line));
	if (memcmp(line, "UPTIME", 6) == 0)
		uptime();
	else
	if (memcmp(line, "LOGROTATE", 9) == 0) {
		if (misc_rotatelog() < 0)
			fprintf(fp, "+ERR logrotate error!\n");
		else
			fprintf(fp, "+OK logrorate successfull!\n");
	} else
	if (memcmp(line, "SHUTDOWN", 8) == 0) {
		fprintf(fp, "+OK SHUTDOWN received!, shutting down the server!!!\n\n");
		graceful_shutdown();
		return;
	} else
	if (memcmp(line, "RUSAGE", 6) == 0)
		rusage();
	else
	if (memcmp(line, "LOADNETS", 8) == 0)
		loadnets();
	else
	if (memcmp(line, "INFO", 4) == 0)
		info();
	else
	if (memcmp(line, "SHCALL", 6) == 0)
		shcall();
	else
	if (memcmp(line, "SHRTCP", 6) == 0)
		shrtcp();
	else
	if (memcmp(line, "KILLCALL", 8) == 0)
		killcall(line);
	else
	if (memcmp(line, "SETDEBUG", 8) == 0)
		setdebug(line);
	else
	if (memcmp(line, "SETMIXFLAG", 10) == 0)
		setmixflag(line);
	else
	if (memcmp(line, "CLOSESESSION", 12) == 0) {
		fprintf(fp, "+OK bye bye\n");
		fflush(fp);
		close_mgmt_client();
	}
	else
		fprintf(fp, "+ERR Invalid command in protocol\n");

	fflush(fp);
}


void 
close_mgmt_client()
{
	misc_debug(0, "Shutting down management console...\n");
	close(mgmtfd);
	remove_from_select_set(mgmtfd);
	mgmtconnected = 0;
	mgmtfd = -1;
	authok = 0;
	passtries = 0;
}
