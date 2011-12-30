
#ifndef MISCUTIL_H
#define MISCUTIL_H


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


#include <sys/time.h>

#define	MISC_LOGFG	1
#define	MISC_LOGBG	0

#define  O_LOGHEX    0x00000001
#define  O_LOGCHAR   0x00000002

#define read_lock(fd) \
        misc_lockreg(fd, F_SETLK, F_RDLCK, 0, SEEK_END, 0)
#define readw_lock(fd) \
        misc_lockreg(fd, F_SETLKW, F_RDLCK, 0, SEEK_END, 0)
#define write_lock(fd) \
        misc_lockreg(fd, F_SETLK, F_WRLCK, 0, SEEK_END, 0)
#define writew_lock(fd) \
        misc_lockreg(fd, F_SETLKW, F_WRLCK, 0, SEEK_END, 0)
#define un_lock(fd) \
        misc_lockreg(fd, F_SETLK, F_UNLCK, 0, SEEK_END, 0)


void misc_setlogtype(int t);	 
void misc_setlogdir(const char *);
void misc_setlogfile(const char *);
void misc_setloglevel(int);
int misc_getlogleve();
int misc_openlog();
int misc_closelog();
void misc_debug(int, char *, ...);
void misc_devmsglog(char *a, int flags, unsigned char *buf, int len);
void misc_devlogx(char *a, int flags, unsigned char *buf, int len, char direction);
void misc_devlog(char *a, char *fmt, ...);
int misc_rotatelog();
char * misc_getunamestr(char *, int);
char * misc_getuptimestr(char *, int, time_t);

char *misc_inet_ntoa(int);
int misc_inet_addr(char *);
char *misc_trim(char *, int);
char *misc_trimnewline(char *, int);
int misc_hexstr2raw(char *str, char *out, int len);
int misc_hexchar2int(char *str);
int misc_substr(char *out, char *in, int offset, int len);
int misc_strftime(char *out, int len, char *fmt);
int misc_strftimegiven(char *out, int len, char *fmt, time_t tv);
int misc_strstr(char *out, int outlen, char *in, int inlen, char sep, int sepix);
double misc_getamount(char *stramount, int currencycode);
double misc_timediff(struct timeval *t2, struct timeval *t1);
int misc_trimnongraph(char *str, int len);
int misc_getdayofmonth(time_t *tv);
int misc_getmonth(time_t *tv);
int misc_getyear(time_t *tv);
char * misc_strbuf(char *hs, int hslen, char *ndl, int ndllen);
int misc_lockreg(int fd, int cmd, int type, int offset, int whence, int len);
void misc_strrev(char *str, int len);

#endif
