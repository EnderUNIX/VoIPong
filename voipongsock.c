
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
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <voipongpcap.h>
#include <voipongmgmt.h>

extern char gmgmt_path[128];
extern int pcapfd;
  

static fd_set allset;
static int mgmtfd = -1;

int
getmaxfd()
{
	int maxfd;
	int mfd = get_mgmt_fd();

	if (mgmtfd > pcapfd)
		maxfd =  mgmtfd;
	else
		maxfd = pcapfd;

	if (mfd > maxfd)
		return mfd;
	else
		return maxfd;
}



void
initsock()
{
	FD_ZERO(&allset);
}

void
add_to_select_set(int sd)
{
	FD_SET(sd, &allset);
}

void
remove_from_select_set(int sd)
{
	FD_CLR(sd, &allset);
} 

int 
open_server_socket()
{
	struct sockaddr_un sun;
	int flags;
	int optval = 1;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_LOCAL;
	/* TODO */
	strncpy(sun.sun_path, gmgmt_path, 96);

	if (unlink(gmgmt_path) == -1) {
		if (errno != ENOENT) {
			misc_debug(0, "cannot delete mmgt IPC mgmt_path %s: %s\n", gmgmt_path, strerror(errno));
			return -1;
		}
	}

	if ((mgmtfd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0) {
		misc_debug(0, "cannot create mgmt server socket: %s\n", strerror(errno));
		return -1;
	}

	if (setsockopt(mgmtfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
		misc_debug(0, "cannot set SO_REUSEADDR socket option: %s\n", strerror(errno));
		return -1;
	}
	
	/* Set socket mode non-blocking	*/
	flags = fcntl(mgmtfd, F_GETFL, 0);
	fcntl(mgmtfd, F_SETFL, flags | O_NONBLOCK);

	if (bind(mgmtfd, (void *)&sun, sizeof(sun)) < 0) {
		misc_debug(0, "cannot bind to mgmt server mgmt_path %s: %s\n", gmgmt_path, strerror(errno));
		return -1;
	}

	if (listen(mgmtfd, 128) < 0) {
		misc_debug(0, "cannot listen server mgmt_path %s: %s\n", gmgmt_path, strerror(errno));
		return -1;
	}
	/* TODO */
	if (chmod(gmgmt_path, 0700) == -1) {
		misc_debug(0, "cannot chmod mgmt_ipcpath[%s]: %s\n", gmgmt_path, strerror(errno));
		return -1;
	}
	add_to_select_set(mgmtfd);
	return 0;
}

void 
sockets_run(void)
{
	fd_set rset;
	struct timeval tv;
	int nready;
	
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	for ( ; ; ) {
		rset = allset;
		if ((nready = select(getmaxfd() + 1, &rset, NULL, NULL, &tv)) < 0) {
			if (errno == EINTR)
				continue;
			misc_debug(0, "select: %s\n", strerror(errno));
			continue;
		}
		if (FD_ISSET(mgmtfd, &rset)) {
			accept_mgmt_client(mgmtfd);
			nready--;
		}

		if (nready > 0 && FD_ISSET(pcapfd, &rset)) {
			peekpcap(100, packet_handler);
			nready--;
		}

		if (nready > 0 && is_mgmt_active()) {
			if (FD_ISSET(get_mgmt_fd(), &rset)) {
				process_mgmt_request();
				nready--;
			}
		}
	}
}
