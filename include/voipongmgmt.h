#ifndef MGMTCONSOLE_H
#define MGMTCONSOLE_H

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


#define	MGMTMAXPASSTRIES	3

#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>

int is_mgmt_active();
void accept_mgmt_client(int);
void process_mgmt_request();
void close_mgmt_client();
int get_mgmt_fd();


#endif
