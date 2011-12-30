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


#include <miscutil.h>
#include <conf.h>

#include <voipongnet.h>
#include <voipongvoip.h>

/* GLOBALS	*/
config cfg;
int gfg = 0;
int gdbg = 0;
char gcfgfile[128];
char gmgmt_path[128];
char gmodpath[256];
int grtp_idle_time = 0;
int gthisday = 0;
int gthismon = 0;
time_t gstarttime = 0;
int mgmt_client = 0;
int gmgmtport = 0;
char gsoxpath[256];
char gsoxmixpath[256];
int gsoxmixflag = 0;
char gpidfile[128];
char goutdir[256];
char gnetfile[256];
char gcdrfile[256];
char gdefalg[256];
int pcapfd = -1, mgmtfd = -1;
char gdevice[256];
char gfilter[1024];
int gpromisc = 1;
int gsnaplen = 1;
int greadtmt = 1;
rtp_session *rtps = NULL;
void (*packet_handler_default) (vnet *, u_char *udata, const struct pcap_pkthdr *pkthdr, const u_char *packet);
