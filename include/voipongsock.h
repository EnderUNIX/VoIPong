
#ifndef VOIPONGSOCKET_H
#define VOIPONGSOCKET_H

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
	Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/


#include <sys/types.h>

#define AUTHCLIRBUFSIZ	8192

int open_server_socket();
void add_to_select_set(int);
void remove_from_select_set(int);
void sockets_run(void);
/*
void init_socket();
void close_all_connections();
void setselecttimeout(int val);
int getselecttimeout(void);
int open_server_socket(int, int *);
*/

#endif
