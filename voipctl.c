/*
	VoIPong Voice Over IP Sniffer
	Copyright (C) 2004,2005 Murat Balaban <murat || enderunix.org>
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
#include <ctype.h>

#include <miscutil.h>
#include <conf.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sysexits.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <voipong.h>
#include <voipongpcap.h>
#include <voipongmgmt.h>

  
/* Externals	*/
extern config cfg;
extern char gcfgfile[128];
extern int gthisday;
extern int gthismon;
extern time_t gstarttime;
extern char gmgmt_path[128];

static int sd = -1;

int process_greets(void);
void process_req(void);
int open_client_socket();
void freecmds(char **cmds, int csiz);

int 
main(int argc, char **argv)
{
	extern char *optarg;
	int error = 0;
	int c = 0;
	struct tm tm;

	/* Program baslarken bugunku tarihi alalim	*/
	time(&gstarttime);
	localtime_r(&gstarttime, &tm);
	gthisday = tm.tm_mday;
	gthismon = tm.tm_mon;

	strcpy(gcfgfile, "/usr/local/etc/voipong/voipong.conf");
	while (!error && (c = getopt(argc, argv, "c:hv")) != -1) {
		switch(c) {
			case 'v':
				printf("%s %s\n", "voipctl", VERSION);
			        printf("Copyright (C) 2005 Murat Balaban <murat || enderunix.org>\n"
					"All rights reserved.\n\n"
					"This program is free software; you can redistribute it and/or\n"
					"modify it under the terms of the GNU General Public License\n"
					"as published by the Free Software Foundation; either version 2\n"
					"of the License, or (at your option) any later version.\n\n"
					"For more information on copying and license, please see LICENSE\n"
					"file included in the voipong source distribution.\n");
				exit(0);
				break;
			case 'h':
				usage();
				exit(0);
				break;
			case 'c':
				strncpy(gcfgfile, optarg, sizeof(gcfgfile) - 2);
				break;
			default:
				printf("invalid option: %c, try -h for help\n", c);
				exit(EX_USAGE);

		}
	}
	init_config();
	if ((sd = open_client_socket()) == -1)
		exit(1);
	process_req();
	return 0;
}

void 
init_config()
{
	char errbuf[CONFERRBUFSIZ];

	if ((config_load(&cfg, gcfgfile, errbuf)) == NULL) {
		fprintf(stderr, "init_config: %s\n", errbuf);
		exit(1);
	}
	get_initcfgvals();
}

void
get_initcfgvals()
{
	if (config_getstr(&cfg, "GENERAL", "mgmt_ipcpath", gmgmt_path, sizeof(gmgmt_path) - 2) == 0) {
		printf("cannot get mgmtipcpath from configfile, shutting down......\n");
		exit(1);
	}
}


void
usage()
{
        printf("usage: voipctl [options]\n");
        printf("\toptions:\n");
        printf("\t\t-h this screen\n");
        printf("\t\t-v version info\n");
        printf("\t\t-c config file path\n");

        printf("\n");
}

int
open_client_socket()
{
	struct sockaddr_un sun;


	memset(&sun, 0x0, sizeof(sun));
	sun.sun_family = AF_LOCAL;
	strncpy(sun.sun_path, gmgmt_path, 100);

	if ((sd = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "open_client_socket: socket: %s\n", strerror(errno));
		return -1;
	}
	if (connect(sd, (const struct sockaddr *)&sun, sizeof(sun)) == -1) {
		fprintf(stderr, "open_client_socket: connect(%s): %s\n", sun.sun_path, strerror(errno));
		return -1;
	}
	if (process_greets() != 0) {
		fprintf(stderr, "open_client_socket: greeting failed with the management server\n");
		return -1;
	}
	return sd;
}

void
prompt()
{
	printf("voipong> ");
	fflush(stdout);
}

int
process_greets(void)
{
	char rbuf[1024];
	int rlen = 0;

	memset(rbuf, 0x0, sizeof(rbuf));
	if ((rlen = recv(sd, rbuf, sizeof(rbuf) - 2, 0)) == -1) {
		fprintf(stderr, "process_greets: recv: %s\n", strerror(errno));
		return -1;
	}
	if (memcmp(rbuf, "+OK", 3) != 0) {
		fprintf(stderr, "process_greets: server did not welcome us:\n%s\n", rbuf);
		return -1;
	}
	printf("\n\n\nConnected to VoIPong Management Console\n\nSystem:\n%s\n\n", rbuf + 4);
	return 0;
}

int
parsecmd(char *str, int siz, char **cmds, int csiz)
{
        char tmp[1024];
        int i = 0, j = 0, k = 0;

        while (i < siz && k < csiz) {
		memset(tmp, 0x0, sizeof(tmp));
                for (; (i < siz) && (!isalnum(str[i])); i++)
                        ;
                for (j = 0; (i < siz) && (isalnum(str[i])) && j < (sizeof(tmp) - 2); i++)
                        tmp[j++] = str[i];
                tmp[j] = '\0';
                if (strlen(tmp) == 0)
                        continue;
                cmds[k++] = strdup(tmp);
        }
        return k;
}

void
freecmds(char **cmds, int csiz)
{
	int i = 0;

	for (i = 0; i < csiz; i++) {
		if (cmds[i] != NULL) {
			free(cmds[i]);
			cmds[i] = NULL;
		}
	}
}

void
help()
{
        printf("Commands:\n");
        printf("help                  : this one\n");
        printf("quit                  : quit management console\n");
        printf("uptime                : Server uptime\n");
        printf("logrotate             : rotate server's logs\n");
        printf("setdebug [level]      : set debug level to [level]\n");
        printf("setmixflag [flag]     : set mix voice flag to true or false [e.g: 1 for true, 0 for false]\n");
        printf("shutdown              : shutdown server\n");
        printf("rusage                : CPU usage statistics for the server\n");
        printf("loadnets              : Reload voipongnets file\n");
        printf("info                  : General server information\n");
        printf("shcall                : Show currently monitored calls\n");
        printf("shrtcp                : Show currently RTCP cache\n");
        printf("killcall [id]         : end monitoring session with [id]\n");
}

int
transport_simplecmd(char *sbuf, int slen, char *rbuf, int rlen)
{
	int ret = 0;

	if ((ret = send(sd, sbuf, slen, 0)) < slen) {
		printf("transport_simplecmd: send (%d): %s\n", ret, strerror(errno));
		return -1;
	}
	memset(rbuf, 0x0, rlen);
	if ((ret = recv(sd, rbuf, rlen, 0)) == -1) {
		printf("transport_simplecmd: recv: %s\n", strerror(errno));
		return -1;
	}
	if (memcmp(rbuf, "+OK", 3) != 0) {
		printf("transport_simplecmd: server returned error: %.128s\n", rbuf + 5);
		return -1;
	}
	return 0;
}

int
transport_advcmd(char *sbuf, int slen, char *rbuf, int rlen)
{
	int ret = 0;
	char *tmp;
	int ntmp = 0;

	if ((ret = send(sd, sbuf, slen, 0)) < slen) {
		printf("transport_advcmd: send (%d): %s\n", ret, strerror(errno));
		return -1;
	}
	memset(rbuf, 0x0, rlen);
	if ((ret = recv(sd, rbuf, rlen, 0)) == -1) {
		printf("transport_advcmd: recv: %s\n", strerror(errno));
		return -1;
	}
	if (memcmp(rbuf, "+OK", 3) != 0) {
		printf("transport_advcmd: server returned error: %.128s\n", rbuf + 5);
		return -1;
	}
	if ((tmp = misc_strbuf(rbuf, ret, "+OK .", 5)) != NULL)
		ntmp = (tmp - rbuf - 5);
	else
		return -1;
	fwrite(rbuf + 5, sizeof(char), ntmp, stdout);
	fflush(stdout);
	while(misc_strbuf(rbuf, ret, "+OK .", 5) == NULL) {
		memset(rbuf, 0x0, rlen);
		if ((ret = recv(sd, rbuf, rlen, 0)) == -1) {
			printf("transport_advcmd: w recv: %s\n", strerror(errno));
			return -1;
		}
		fwrite(rbuf, sizeof(char), ret, stdout);
		fflush(stdout);
	}
	return 0;
}

void
uptime(char **cmds, int cnt)
{
	char buf[1024];

	if (transport_simplecmd("UPTIME\r\n", 8, buf, sizeof(buf) - 2) == -1) {
		printf("cannot retrieve uptime information\n");
		return;
	}
	printf("Server uptime: %s\n", buf + 4);
}

void
logrotate(char **cmds, int cnt)
{
	char buf[1024];

	if (transport_simplecmd("LOGROTATE\r\n", 11, buf, sizeof(buf) - 2) == -1) {
		printf("cannot rotate logs\n");
		return;
	}
	printf("Logrotate successfull\n");
}

void
loadnets(char **cmds, int cnt)
{
	char buf[1024];

	if (transport_simplecmd("LOADNETS\r\n", 10, buf, sizeof(buf) - 2) == -1) {
		printf("cannot load voipongnets\n");
		return;
	}
	printf("Networks file has been reloaded successfull\n");
}

void
sshutdown(char **cmds, int cnt)
{
	char buf[1024];

	if (transport_simplecmd("SHUTDOWN\r\n", 10, buf, sizeof(buf) - 2) == -1) {
		printf("cannot send shutdown command\n");
		return;
	}
	exit(0);
}

void
sendclose(char **cmds, int cnt)
{
	char buf[1024];

	if (transport_simplecmd("CLOSESESSION\r\n", 14, buf, sizeof(buf) - 2) == -1) {
		printf("cannot send closesession command\n");
		return;
	}
}

void
rusage(char **cmds, int cnt)
{
	char buf[1024];

	if (transport_advcmd("RUSAGE\r\n", 8, buf, sizeof(buf) - 2) == -1) {
		printf("cannot process rusage command\n");
		return;
	}
}

void
info(char **cmds, int cnt)
{
	char buf[1024];

	if (transport_advcmd("INFO\r\n", 6, buf, sizeof(buf) - 2) == -1) {
		printf("cannot process info command\n");
		return;
	}
}

void
shcall(char **cmds, int cnt)
{
	char buf[1024];

	if (transport_advcmd("SHCALL\r\n", 8, buf, sizeof(buf) - 2) == -1) {
		printf("cannot process shcall command\n");
		return;
	}
}

void
shrtcp(char **cmds, int cnt)
{
	char buf[1024];

	if (transport_advcmd("SHRTCP\r\n", 8, buf, sizeof(buf) - 2) == -1) {
		printf("cannot process shrtcp command\n");
		return;
	}
}

void
killcall(char **cmds, int cnt)
{
	char sbuf[1024];
	char buf[1024];

	if (cmds[1] == NULL)
		return;
	if (strlen(cmds[1]) < 1)
		return;

	snprintf(sbuf, sizeof(sbuf) - 2, "KILLCALL %.20s\r\n", cmds[1]);
	if (transport_simplecmd(sbuf, strlen(sbuf), buf, sizeof(buf) - 2) == -1) {
		printf("cannot process killcall command\n");
		return;
	}
	printf("# %s\n", buf + 4);
}

void
setdebug(char **cmds, int cnt)
{
	char sbuf[1024];
	char buf[1024];

	if (cmds[1] == NULL)
		return;
	if (strlen(cmds[1]) < 1)
		return;

	snprintf(sbuf, sizeof(sbuf) - 2, "SETDEBUG %.20s\r\n", cmds[1]);
	if (transport_simplecmd(sbuf, strlen(sbuf), buf, sizeof(buf) - 2) == -1) {
		printf("cannot process setdebug command\n");
		return;
	}
	printf("# %s\n", buf + 4);
}

void
setmixflag(char **cmds, int cnt)
{
	char sbuf[1024];
	char buf[1024];

	if (cmds[1] == NULL)
		return;
	if (strlen(cmds[1]) < 1)
		return;

	snprintf(sbuf, sizeof(sbuf) - 2, "SETMIXFLAG %.20s\r\n", cmds[1]);
	if (transport_simplecmd(sbuf, strlen(sbuf), buf, sizeof(buf) - 2) == -1) {
		printf("cannot process setmixflag command\n");
		return;
	}
	printf("# %s\n", buf + 4);
}

void
process_req(void)
{
	char line[1024];
	char prevline[1024];
	char *cmds[10];
	int ccnt = 0;

	memset(line, 0x0, sizeof(line));
	memset(prevline, 0x0, sizeof(prevline));
	prompt();
	while (fgets(line, sizeof(line) - 1, stdin) != NULL) {
		ccnt = 0;
		memset(cmds, 0x0, sizeof(cmds));
		misc_trimnewline(line, strlen(line));
		if (strlen(line) == 0) {
			prompt();
			continue;
		}
		if (memcmp(line, "!!", 2) == 0) {
			if (strlen(prevline) == 0) {
				prompt();
				continue;
			}
			strncpy(line, prevline, sizeof(line) - 2);
		}
		if ((ccnt = parsecmd(line, strlen(line), cmds, sizeof(cmds) / sizeof(char *))) < 1) {
			printf("cannot parse command: %s\n", line);
			freecmds(cmds, sizeof(cmds) / sizeof(char *));
			prompt();
			continue;
		}
		if (cmds[0] == NULL)
			continue;

		strncpy(prevline, line, sizeof(prevline) - 2);
		/* Here it is: */
		if (memcmp(cmds[0], "q", 1) == 0 ||
				memcmp(cmds[0], "quit", 4) == 0 ||
				memcmp(cmds[0], "exit", 4) == 0 ||
				memcmp(cmds[0], "bye", 3) == 0) {
			printf("Bye!\n");
			sendclose(cmds, ccnt);
			close(sd);
			return;
		} else
		if (memcmp(cmds[0], "help", 4) == 0)
			help();
		else
		if (memcmp(cmds[0], "uptime", 5) == 0)
			uptime(cmds, ccnt);
		else
		if (memcmp(cmds[0], "logrotate", 9) == 0)
			logrotate(cmds, ccnt);
		else
		if (memcmp(cmds[0], "shutdown", 8) == 0)
			sshutdown(cmds, ccnt);
		else
		if (memcmp(cmds[0], "rusage", 6) == 0)
			rusage(cmds, ccnt);
		else
		if (memcmp(cmds[0], "info", 4) == 0)
			info(cmds, ccnt);
		else
		if (memcmp(cmds[0], "shcall", 6) == 0)
			shcall(cmds, ccnt);
		else
		if (memcmp(cmds[0], "shrtcp", 6) == 0)
			shrtcp(cmds, ccnt);
		else
		if (memcmp(cmds[0], "killcall", 8) == 0)
			killcall(cmds, ccnt);
		else
		if (memcmp(cmds[0], "setdebug", 8) == 0)
			setdebug(cmds, ccnt);
		else
		if (memcmp(cmds[0], "setmixflag", 8) == 0)
			setmixflag(cmds, ccnt);
		else
		if (memcmp(cmds[0], "loadnets", 8) == 0)
			loadnets(cmds, ccnt);

		freecmds(cmds, sizeof(cmds) / sizeof(char *));
		prompt();
	}
	printf("Closing management console...\n");
	close(sd);
}
