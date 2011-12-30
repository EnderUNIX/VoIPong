
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
	Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, 		USA.
*/


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include <sysexits.h>
#include <pcap.h>
#include <fcntl.h>
#include <paths.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <voipong.h>
#include <voipongsign.h>
#include <voipongsock.h>
#include <voipongcodec.h>
#include <voipongpcap.h>
#include <voipongworker.h>
#include <voipongnet.h>

#include <miscutil.h>
#include <conf.h>

/* Externals	*/
extern config cfg;
extern int gfg;
extern int gdbg;
extern char gcfgfile[128];
extern int gthisday;
extern int gthismon;
extern time_t gstarttime;
extern char gsoxpath[256];
extern char gsoxmixpath[256];
extern int gsoxmixflag;
extern char gpidfile[128];
extern char goutdir[256];
extern char gmodpath[256];
extern char gnetfile[256];
extern char gcdrfile[256];
extern char gdefalg[256];
extern int pcapfd, mgmtfd;
extern char gdevice[256];
extern char gfilter[1024];
extern char gmgmt_path[128];
extern int gpromisc;
extern int gsnaplen;
extern int greadtmt;
extern int grtp_idle_time;
extern rtp_session *rtps;
extern void (*packet_handler_default) (vnet *, u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int
daemon_init(void)
{
	FILE *lckp = NULL;
	pid_t pid = 0;
	int i = 0;

	if (gfg == 0) {
		if ((pid = fork()) < 0)
			return -1;
		else if (pid != 0)
			exit(0);
	
		setsid();
		/* fork again so that I cannot gain controlling terminal anymore */
		if ((pid = fork()) < 0)
			return -1;
		else if (pid != 0)
			exit(0);

		for (i = getdtablesize(); i >= 0; i--)
			close(i);
		if ((i = open(_PATH_DEVNULL, O_RDWR, 0640)) == -1) /* stdin */
			exit(1);
		dup2(i, STDOUT_FILENO); 
		dup2(i, STDERR_FILENO);
	}
	setuid(getuid());
	setgid(getgid());
	umask(077);
	openlog("voipong", 0, LOG_DAEMON);
	if ((lckp = fopen(gpidfile, "w")) == NULL) {
		fprintf(stderr, "cannot open pidfile: %s\n", strerror(errno));
		syslog(LOG_WARNING, "cannot open pidfile: %.128s\n", strerror(errno));
		exit(1);
	}
	if (lockf(fileno(lckp), F_TLOCK, 0)) {
		fprintf(stderr, "cannot lock pidfile %s: %s, may be another copy running?\n", gpidfile, strerror(errno));
		syslog(LOG_WARNING, "cannot lock pidfile %.128s: %.128s, may be another copy running?\n", gpidfile, strerror(errno));
		exit(1);
	}
	/* write pid */
	fprintf(lckp, "%d\n", getpid());
	fflush(lckp);
	return 0;
}
	
void 
wexit(int c)
{
	char tmp[1024];

	misc_debug(0, "PID %d [parent: %d]: exited with code: %d. uptime: %s.\n", getpid(), getppid(), c, 
								misc_getuptimestr(tmp, sizeof(tmp) - 2, gstarttime));
	if (unlink(gpidfile) == -1)
		syslog(LOG_ERR, "can't remove  pidfile[%.128s]: %.128s\n", gpidfile, strerror(errno));
	if (unlink(gmgmt_path) == -1)
		syslog(LOG_ERR, "can't remove mgmt_ipcfile[%.128s]: %.128s\n", gmgmt_path, strerror(errno));
	misc_closelog();
	exit(c);
}

int 
main(int argc, char **argv)
{
	extern char *optarg;
	int error = 0;
	int c = 0;
	char tmp[512];
	struct tm tm;
	struct sigaction sa;
	struct sigaction sa_old;
	char errbuf[ERRBUFSIZ];

	sa.sa_handler = sighandler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGHUP, &sa, &sa_old);
	sigaction(SIGUSR2, &sa, &sa_old);
	sigaction(SIGTERM, &sa, &sa_old);
	sigaction(SIGINT, &sa, &sa_old);
	sigaction(SIGCHLD, &sa, &sa_old);
	sigaction(SIGSTOP, &sa, &sa_old);
	sigaction(SIGQUIT, &sa, &sa_old);
	sigaction(SIGPIPE, &sa, &sa_old);
	sigaction(SIGALRM, &sa, &sa_old);

	/* Program baslarken bugunku tarihi alalim	*/
	time(&gstarttime);
	localtime_r(&gstarttime, &tm);
	gthisday = tm.tm_mday;
	gthismon = tm.tm_mon;

	strcpy(gcfgfile, "/usr/local/etc/voipong/voipong.conf");
	while (!error && (c = getopt(argc, argv, "c:d:hvf")) != -1) {
		switch(c) {
			case 'v':
				printf("%s %s\n", PROGRAM, VERSION);
			        printf("Copyright (C) 2004 Murat Balaban <murat || enderunix.org>\n"
					"All rights reserved.\n\n"
					"This program is free software; you can redistribute it and/or\n"
					"modify it under the terms of the GNU General Public License\n"
					"as published by the Free Software Foundation; either version 2\n"
					"of the License, or (at your option) any later version.\n\n"
					"For more information on licensing, please see LICENSE\n"
					"file included in the voipong source distribution.\n");
				exit(0);
				break;
			case 'h':
				usage();
				exit(0);
				break;
			case 'f':
				gfg = 1;
				break;
			case 'd':
				gdbg = atoi(optarg);
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
	misc_setlogtype(gfg);
	misc_setlogdir(config_getval(&cfg, "GENERAL", "logdir"));
	misc_setlogfile(config_getval(&cfg, "GENERAL", "logfile"));
	misc_setloglevel(gdbg);
	printf("%s starting...\n", PROGRAM);
	printf("%s, running on %s\n\n", VERSION, misc_getunamestr(tmp, sizeof(tmp) - 2));
	printf("%s\n", COPYRIGHT);
	daemon_init();
	if (misc_openlog() < 0) {
		syslog(LOG_ERR, "misc_openlog: error!: %.128s", strerror(errno));
		wexit(1);
	}
	misc_debug(0, "%s starting...\n", PROGRAM);
	misc_debug(0, "%s running on %s. %s [pid: %d]\n", VERSION, misc_getunamestr(tmp, 512), COPYRIGHT, getpid());
	misc_debug(0, "Default matching algorithm: %s\n", gdefalg);
	init_voip();
	init_workers();
	init_vnet();
	init_vocoders();
	loadnetfile(gnetfile);
	if ((pcapfd = initpcap(1, gfilter, errbuf)) == -1) {
		misc_debug(0, "libpcap start failure: %s\n", errbuf);
		wexit(1);
	}
	add_to_select_set(pcapfd);
	if (open_server_socket() == -1) {
		misc_debug(0, "mgmt socket open failure!\n");
		wexit(1);
	}
	sockets_run();
	wexit(0);
	return 0;
}

void 
graceful_shutdown()
{
	kill_workers();
	wexit(0);
}

void 
reload()
{


}

void 
init_config()
{
	char errbuf[CONFERRBUFSIZ];

	if ((config_load(&cfg, gcfgfile, errbuf)) == NULL) {
		fprintf(stderr, "init_config: %s\n", errbuf);
		wexit(1);
	}
	get_initcfgvals();
}

void
get_initcfgvals()
{
	if (config_getstr(&cfg, "GENERAL", "mgmt_ipcpath", gmgmt_path, sizeof(gmgmt_path) -2) == 0) {
		printf("cannot get mgmtipcpath from configfile, shutting down......\n");
		exit(1);
	}
	if (config_getstr(&cfg, "GENERAL", "pidfile", gpidfile, sizeof(gpidfile) - 2) == 0) {
		printf("cannot get pidfile from configfile, shutting down......\n");
		exit(1);
	}
	if ((grtp_idle_time = config_getint(&cfg, "GENERAL", "rtp_idle_time", -1)) == -1) {
		printf("cannot get rtp_idle_time from configfile, shutting down......\n");
		exit(1);
	}

	if (config_getstr(&cfg, "GENERAL", "outdir", goutdir, sizeof(goutdir) - 2) == 0) {
		printf("cannot get outdir from configfile, shutting down......\n");
		exit(1);
	}
	if (config_getstr(&cfg, "GENERAL", "cdrfile", gcdrfile, sizeof(gcdrfile) - 2) == 0) {
		printf("cannot get cdrfile from configfile, shutting down......\n");
		exit(1);
	}
	if (config_getstr(&cfg, "GENERAL", "soxpath", gsoxpath, sizeof(gsoxpath) - 2) == 0) {
		printf("cannot get soxpath from configfile, shutting down......\n");
		exit(1);
	}
	if (config_getstr(&cfg, "GENERAL", "soxmixpath", gsoxmixpath, sizeof(gsoxmixpath) - 2) == 0) {
		printf("cannot get soxmixpath from configfile, shutting down......\n");
		exit(1);
	}
	gsoxmixflag = config_getint(&cfg, "GENERAL", "mixwaves", 0);
	if (config_getstr(&cfg, "GENERAL", "defalg", gdefalg, sizeof(gdefalg) - 2) == 0) {
		printf("cannot get gdefalg from configfile, shutting down......\n");
		exit(1);
	}
	if (config_getstr(&cfg, "GENERAL", "modpath", gmodpath, sizeof(gmodpath) - 2) == 0) {
		printf("cannot get modpath from configfile, shutting down......\n");
		exit(1);
	}
	if (strcmp(gdefalg, "lfp") == 0)
		packet_handler_default = packet_handler_lfp;
	else
	if (strcmp(gdefalg, "lra") == 0) {
		printf("This matching algorithm is not implemented yet!\n");
		/*packet_handler_default = packet_handler_lra;	*/
		exit(1);
	}
	else {
		printf("Default packet matching algorithm should be selected: (lfp/lra) wrong input: %s\n", gdefalg);
		exit(1);
	}
	config_getstr(&cfg, "FILTERS", "startup_filter", gfilter, sizeof(gfilter) - 2);
	config_getstr(&cfg, "GENERAL", "device", gdevice, sizeof(gdevice) - 2);
	config_getstr(&cfg, "GENERAL", "networksfile", gnetfile, sizeof(gdevice) - 2);

	if ((gpromisc = config_getint(&cfg, "GENERAL", "promisc", -1)) == -1) {
		printf("cannot get promisc value from configfile, shutting down......\n");
		exit(1);
	}

	if ((gsnaplen = config_getint(&cfg, "GENERAL", "snaplen", -1)) == -1) {
		printf("cannot get snaplen value from configfile, shutting down......\n");
		exit(1);
	}
	if ((greadtmt = config_getint(&cfg, "GENERAL", "readtmt", -1)) == -1) {
		printf("cannot get readtmt value from configfile, shutting down......\n");
		exit(1);
	}

}


void
usage()
{
        printf("usage: voipong [options]\n");
        printf("\toptions:\n");
        printf("\t\t-h this screen\n");
        printf("\t\t-v version info\n");
        printf("\t\t-f run in foreground (don't become a daemon)\n");
        printf("\t\t-d debug level. Valid levels are 0 through 4. Default: 0\n");
        printf("\t\t-c config file path\n");

        printf("\n");
}

void
process_deadchild()
{
	pid_t pid;
	int stat = 0;
	int termsig = 0, exitcode = 0;
	struct sigaction sa;
	worker *w;

	sigemptyset(&sa.sa_mask);
	sigaddset(&(sa.sa_mask), SIGCHLD);
	sigprocmask(SIG_BLOCK, &(sa.sa_mask), NULL);

	if ((pid = wait(&stat)) == -1) {
		misc_debug(0, "process_deadchild: wait error: %s\n", strerror(errno));
		return;
	}
	if ((w = getworkerbypid(pid)) == NULL) {
		misc_debug(0, "I dont have a child with pid %d\n", pid);
		return;
	}
	if (WIFEXITED(stat))
		misc_debug(0, "child [pid: %d] terminated normally [exit code: %d]\n", pid, (exitcode = WEXITSTATUS(stat)));
	else
	if (WIFSIGNALED(stat))
		misc_debug(0, "child [pid: %d] terminated by signal %d\n", pid, (termsig = WTERMSIG(stat)));
	worker_remove(w);
	free(w);
}
