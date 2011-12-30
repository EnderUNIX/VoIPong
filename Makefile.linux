#
#	VoIPong Voice Over IP Sniffer
#	Copyright (C) 2005 Murat Balaban <murat || enderunix.org>
#	All rights reserved.
#
#	This program is free software; you can redistribute it and/or
#	modify it under the terms of the GNU General Public License
#	as published by the Free Software Foundation; either version 2
#	of the License, or (at your option) any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

CC=cc
CFLAGS= -g -Wall -Iinclude
SHLIBS=-lpcap -ldl

CLEARX = rm -f *~ *core* *pid



OBJS= miscutil.o conf.o voipongglobals.o voipongsign.o voipong.o  voipongsock.o \
      voipongnet.o voipongpcap.o voipongvoip.o voipongmgmt.o voipongworker.o \
      voipongcdr.o voipongcodec.o voiponglfp.o voipongfixed.o

all:  modules voipong voipctl

voipong: $(OBJS)
	$(CLEARX)
	$(CC) -g -o voipong $(CFLAGS) $(LDFLAGS) $(OBJS) $(STLIBS) $(SHLIBS)

voipctl: voipctl.o voipongglobals.o
	$(CLEARX)
	$(CC) -g -o voipctl voipctl.o voipongglobals.o conf.o miscutil.o $(CFLAGS) 

modules: modvocoder_pcmu modvocoder_pcma

modvocoder_pcmu:
	$(CLEARX)
	$(CC) -fPIC $(CFLAGS) -c modvocoder_pcmu.c
	$(CC) -shared -nostdlib -o modvocoder_pcmu.so modvocoder_pcmu.o

modvocoder_pcma:
	$(CLEARX)
	$(CC) -fPIC $(CFLAGS) -c modvocoder_pcma.c
	$(CC) -shared -nostdlib -o modvocoder_pcma.so modvocoder_pcma.o

install:
	mkdir -p /usr/local/etc/voipong
	mkdir -p /usr/local/etc/voipong/modules
	cp voipong /usr/local/bin/
	cp voipctl /usr/local/bin/
	cp etc/voipong.conf /usr/local/etc/voipong/
	chmod 750 /usr/local/bin/voipong
	chmod 750 /usr/local/bin/voipctl
	chmod 600 /usr/local/etc/voipong/voipong.conf
	cp modvocoder_*.so /usr/local/etc/voipong/modules/
	chmod 500 /usr/local/etc/voipong/modules/*

cls:
	$(CLEARX)

clean:
	$(CLEARX)
	rm -f voipong voipctl $(OBJS) *.o *.so *~
