/*
        VoIPong Voice Over IP Sniffer
        Copyright (C) 2005 Murat Balaban <murat || enderunix.org>
        All rights reserved.


	G711 PCMA (a-law) Decoder Module


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


/*
 * This source code is a product of Sun Microsystems, Inc. and is provided
 * for unrestricted use.  Users may copy or modify this source code without
 * charge.
 *
 * SUN SOURCE CODE IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING
 * THE WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 *
 * Sun source code is provided with no support and without any obligation on
 * the part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 *
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY THIS SOFTWARE
 * OR ANY PART THEREOF.
 *
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 *
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */



#include <unistd.h>
#include <netinet/in_systm.h>
#include <voipongcodec.h>


/* modvocoder_pcma.c
 *
 * Module Definitions
 *
 */

#define	MODNAME	"VOIPONG vocoder G711 (a-law)"
#define	MODVERSION	"1.0"
#define	MODPAYLOADTYPE	8
#define	MODPAYLOADRATE	8000


/*
 * g711.c
 *
 * u-law, A-law and linear PCM conversions.
 */
#define	SIGN_BIT	(0x80)		/* Sign bit for a A-law byte. */
#define	QUANT_MASK	(0xf)		/* Quantization field mask. */
#define	NSEGS		(8)		/* Number of A-law segments. */
#define	SEG_SHIFT	(4)		/* Left shift for segment number. */
#define	SEG_MASK	(0x70)		/* Segment field mask. */

/*
 * alaw2linear() - Convert an A-law value to 16-bit linear PCM
 *
 */
static int
alaw2linear(
	unsigned char	a_val)
{
	int		t;
	int		seg;

	a_val ^= 0x55;

	t = (a_val & QUANT_MASK) << 4;
	seg = ((unsigned)a_val & SEG_MASK) >> SEG_SHIFT;
	switch (seg) {
	case 0:
		t += 8;
		break;
	case 1:
		t += 0x108;
		break;
	default:
		t += 0x108;
		t <<= seg - 1;
	}
	return ((a_val & SIGN_BIT) ? t : -t);
}

/* Decodes one byte PCMU data to two bytes unsigned linear data */
static int
vocoder_alaw(int fd, u_char *pl, int len)
{
	u_int16_t wbuf[2048];
	int i = 0;
	int wlen = len * sizeof(u_int16_t);

	for (i = 0; i < len && (i < sizeof(wbuf) / sizeof(u_int16_t)); i++)
		wbuf[i] = alaw2linear(pl[i]);
	if (write(fd, wbuf, wlen) < wlen)
		return -1;
	return wlen;
}

/* Install module hook */
vocoder_t *
modvocoder_pcma_init(vocoder vocoders[])
{
	vocoders[MODPAYLOADTYPE].rate = MODPAYLOADRATE;
	vocoders[MODPAYLOADTYPE].f = vocoder_alaw;
	return (vocoder_t *)vocoders[MODPAYLOADTYPE].f;
}
