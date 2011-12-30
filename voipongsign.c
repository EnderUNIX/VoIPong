
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


#include <signal.h>
#include <string.h>
#include <errno.h>


#include <voipong.h>
#include <miscutil.h>
#include <voipongsign.h>
#include <voipongworker.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

extern void wexit(int);
extern int gmainprocess;

void 
sigint_handler()
{
	misc_debug(0, "INTERRUPT signal caught, starting shutdown procedures...\n");
	wexit(0);
}


void sigusr2_handler()
{
}

void
sigalrm_handler()
{
}

void
sigterm_handler()
{
	misc_debug(0, "SHUTDOWN signal caught, starting shutdown procedures...\n");
	graceful_shutdown();
	wexit(0);
}


void
sigworkeralrm_handler()
{
}

void
sigworkerterm_handler()
{
	misc_debug(0, "SHUTDOWN signal caught, starting shutdown procedures...\n");
	worker_graceful_exit(0);
}



void sighandler(int signal)
{
	switch(signal) {
		case SIGCHLD:
			process_deadchild();
			break;
		case SIGINT:
			sigterm_handler();
			break;
		case SIGTERM:
			sigterm_handler();
			break;
		case SIGKILL:
			sigterm_handler();
			break;
		case SIGPIPE:
			break;
		case SIGALRM:
			sigalrm_handler();
			break;
		case SIGUSR2:
			sigusr2_handler();
			break;
		default:
			break;
	}
}

void sigworkerhandler(int signal)
{
	switch(signal) {
		case SIGINT:
		case SIGTERM:
			sigworkerterm_handler();
			break;
		case SIGPIPE:
			break;
		case SIGALRM:
			sigworkeralrm_handler();
			break;
		default:
			break;
	}
}
