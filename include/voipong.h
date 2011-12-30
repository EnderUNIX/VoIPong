
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

#ifndef VOIPONG_H
#define VOIPONG_H

#define PROGRAM	"EnderUNIX VOIPONG Voice Over IP Sniffer"
#define VERSION "Release 2.0"
#define COPYRIGHT "(c) Murat Balaban http://www.enderunix.org/"

#include <voipongvoip.h>

enum {
	ERRBUFSIZ = 1024,
	MAXSBUFSIZ = 128,
	MAXMBUFSIZ = 512,
	MAXBUFSIZ = 1024,
	MAXLBUFSIZ = 2048,
	MAXXBUFSIZ = 4096,
	MAXXXBUFSIZ = 8192
};

void graceful_shutdown();
void reload();
void usage();
void wexit(int);
void waitforevents(void);
void process_deadchild(void);
	  
void init_config();
void get_initcfgvals();


#endif
