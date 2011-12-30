
#ifndef VOIPONGNET_H
#define VOIPONGNET_H

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


#include <sys/types.h>
#include <pcap.h>

enum algos {
	ALGORITHM_LFP = 1,
	ALGORITHM_LRA = 2,
	ALGORITHM_FIXED
};



typedef struct vnet vnet;
struct vnet {
	int addr;
	int mask;
	int algo;
	int fixport;
	short inuse;
	void (*op) (struct vnet *, unsigned char *udata, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);
	struct vnet *next;
};


int loadnetfile(char *netfile);
void init_vnet();
void free_vnet();
vnet *get_vnet();

#endif
