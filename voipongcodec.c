/*
        VoIPong Voice Over IP Sniffer
        Copyright (C) 2005 Murat Balaban <murat || enderunix.org>
        All rights reserved.


	Decoder Modules Interfaces


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
        Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,          USA.


*/


#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <dirent.h>

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
#include <g711.h>

#include <voipong.h>
#include <voipongvoip.h>
#include <voipongworker.h>
#include <voipongpcap.h>
#include <voipongcodec.h>

extern char gmodpath[256];

vocoder vocoders[MAXCODECS];

int
vocoder_default(int fd, u_char *pl, int len)
{
	if (write(fd, pl, len) < len) {
		misc_debug(0, "dumppl_default: write: %s\n", strerror(errno));
		return -1;
	}
	return len;
}

void
getmodinitfunc(char *initstr, short initlen, char *mpath)
{
	int i = 0, j = 0;
	char modname[128];

	for (i = strlen(mpath) - 1, j = 0; i > 0 && j < sizeof(modname) - 6; i--) {
		if (mpath[i] == '/')
			break;
		modname[j++] = mpath[i];
	}
	modname[j] = '\0';
	misc_strrev(modname, strlen(modname)); 
	strncpy(initstr, modname, initlen - 6);
	memcpy(initstr + (strlen(initstr) - 3), "_init", 5);
}

int
loadmodule(char *path)
{
	void * ld;
	const char *errstr = NULL;
	char initstr[128];
	vocoder_t * (*f) (vocoder vocoders[]);
	void *addr = NULL;

	if ((ld = dlopen(path, RTLD_NOW)) == NULL) {
		misc_debug(0, "loadmodule: dlopen(%s): %s\n", path, dlerror());
		return -1;
	}
	getmodinitfunc(initstr, sizeof(initstr) - 2, path);
	f = dlsym(ld, initstr);
	if ((errstr = dlerror()) != NULL) {
		misc_debug(0, "loadmodule (%s): dlsym: %s\n", path, errstr);
		dlclose(ld);
		return -1;
	}
	addr = (*f) (vocoders);
	misc_debug(0, "loadmodule: %s (@%p)\n", path, addr);
	return 0;
}


/* Try to avoid some "really nasty" actions... */
int
securemod(struct stat *st, char *fname)
{
	if (strlen(fname) < 7) {
		misc_debug(0, "error: securemod(%s): invalid module naming", fname);
		return 0;
	}
	if (st->st_uid != getuid()) {
		misc_debug(0, "error: securemod(%s): uid: got %d, expected %d\n", fname, st->st_uid, getuid());
		return 0;
	}
	if (st->st_gid != getgid()) {
		misc_debug(0, "error: securemod(%s): gid: got %d, expected %d\n", fname, st->st_gid, getgid());
		return 0;
	}
	if (st->st_mode & S_IWGRP) {
		misc_debug(0, "error: securemod(%s): module has group-writable bit set\n", fname);
		return 0;
	}
	if (st->st_mode & S_IWOTH) {
		misc_debug(0, "error: securemod(%s): module has world-writable bit set\n", fname);
		return 0;
	}
	if (S_ISLNK(st->st_mode)) {
		misc_debug(0, "error: securemod(%s): module cannot be a symbolic link\n", fname);
		return 0;
	}
	return 1;
}

void
init_vocoders()
{
	char fname[1024];
	DIR *dirp;
	struct dirent *dp;
	int i = 0;
	struct stat st;
	int cnt = 0;

	for (i = 0; i < MAXCODECS; i++) {
		vocoders[i].f = vocoder_default;
		vocoders[i].rate = 0;
	}
	if ((dirp = opendir(gmodpath)) == NULL) {
		misc_debug(0, "init_vocoders: cannot open modules dir %s: %s\n", gmodpath, strerror(errno));
		return;
	}
	while((dp = readdir(dirp)) != NULL) {
		if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0 || (memcmp(dp->d_name, "mod", 3) != 0))
			continue;
		snprintf(fname, sizeof(fname) - 2, "%s/%s", gmodpath, dp->d_name);
		stat(fname, &st);
		if (S_ISREG(st.st_mode)) 
			if (securemod(&st, fname))
				if (loadmodule(fname) == 0)
					cnt++;
	}
	misc_debug(0, "loaded %d module(s)\n", cnt);
}
