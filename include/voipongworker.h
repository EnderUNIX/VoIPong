#ifndef ___WORKER_H
#define ___WORKER_H

#include <time.h>

#include <voipong.h>
#include <voipongvoip.h>
typedef struct worker worker;

struct worker {
	pid_t pid;
	rtcp_session *rtcp;
	rtp_session *rtp;
	int ip1fd;
	int ip2fd;
	char file1name[MAXLBUFSIZ];
	char file2name[MAXLBUFSIZ];
	time_t stime;
	time_t etime;
	struct worker *next;
};

void init_workers();
void worker_main(worker *, int, unsigned char *);
void kill_workers();
worker *getworkerbypid(pid_t );
void worker_remove(worker *);
int worker_create(worker **, int, unsigned char *);
int worker_isexist(u_int32_t, u_int32_t, u_int16_t, u_int16_t);
int create_wave();
int exec_sox(char *, char *, char *, char *, char *);
int exec_soxmix(char *, char *, char *);
int create_outpath();
void worker_graceful_exit(int);

void dumprtppayload(u_char *, const struct pcap_pkthdr *, const u_char *);


#endif
