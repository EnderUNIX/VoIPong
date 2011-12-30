/*
        VoIPong Voice Over IP Sniffer
        Copyright (C) 2005 Murat Balaban <murat || enderunix.org>
        All rights reserved.


	G711 PCMU (u-law) Decoder Module


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


/* modvocoder_pcmu.c
 *
 * Module Definitions
 */

#define	MODNAME	"VOIPONG vocoder G711 (u-law)"
#define	MODVERSION	"1.0"
#define	MODPAYLOADTYPE	0
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

#define	BIAS		(0x84)		/* Bias for linear code. */


/*
 * ulaw2linear() - Convert a u-law value to 16-bit linear PCM
 *
 * First, a biased linear code is derived from the code word. An unbiased
 * output can then be obtained by subtracting 33 from the biased code.
 *
 * Note that this function expects to be passed the complement of the
 * original code word. This is in keeping with ISDN conventions.
 */
static int
ulaw2linear(
	unsigned char	u_val)
{
	int		t;

	/* Complement to obtain normal u-law value. */
	u_val = ~u_val;

	/*
	 * Extract and bias the quantization bits. Then
	 * shift up by the segment number and subtract out the bias.
	 */
	t = ((u_val & QUANT_MASK) << 3) + BIAS;
	t <<= ((unsigned)u_val & SEG_MASK) >> SEG_SHIFT;

	return ((u_val & SIGN_BIT) ? (BIAS - t) : (t - BIAS));
}

/* Decodes one byte PCMU data to two bytes unsigned linear data */
static int
vocoder_ulaw(int fd, u_char *pl, int len)
{
	u_int16_t wbuf[2048];
	int i = 0;
	int wlen = len * sizeof(u_int16_t);

	for (i = 0; i < len && (i < sizeof(wbuf) / sizeof(u_int16_t)); i++)
		wbuf[i] = ulaw2linear(pl[i]);
	if (write(fd, wbuf, wlen) < wlen)
		return -1;
	return wlen;
}

/* Install module hook */
vocoder_t *
modvocoder_pcmu_init(vocoder vocoders[])
{
	vocoders[MODPAYLOADTYPE].rate = MODPAYLOADRATE;
	vocoders[MODPAYLOADTYPE].f = vocoder_ulaw;
	return (vocoder_t *)vocoders[MODPAYLOADTYPE].f;
}
