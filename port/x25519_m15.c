/*
 * Copyright (c) 2017 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * X25519 for cores without a 32x32->64 multiply (ESP8266, Cortex-M0+) using
 * BearSSL's "m15" Curve25519 field arithmetic (13-bit limbs, 32-bit
 * products). On those cores libsodium's ref10 ladder spends most of its time
 * in software 64-bit products; the m15 representation needs none. Only the
 * variable-base ladder lives here: the base point multiply keeps ref10's
 * precomputed Edwards tables, which beat a ladder even on these cores.
 *
 * The field code is taken unchanged from BearSSL src/ec/ec_c25519_m15.c
 * (MIT, see above). The ladder takes the little endian X25519 scalar and
 * point directly, reuses temporaries to keep the stack small, and on the
 * ESP8266 yields to the SYS context once per iteration like the ref10
 * ladder does (a no-op elsewhere).
 */

#include "sodium/esphome_x25519_m15.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sodium/utils.h>

#include "sodium/esphome_yield.h"

#define MUL15(x, y)   ((uint32_t)(x) * (uint32_t)(y))

/*
 * Arithmetic right shift of a 32-bit word. BearSSL reads the word through
 * an int32_t pointer; the value cast below has the same effect on every
 * compiler this port targets (gcc and clang define the conversion as
 * wrapping and the shift as arithmetic) without the type pun.
 */
#define ARSH(x, n)   (((int32_t)(x)) >> (n))

/*
 * Copy src to dst when ctl is 1, leave dst untouched when ctl is 0,
 * without branching on ctl.
 */
static void
ccopy(uint32_t ctl, void *dst, const void *src, size_t len)
{
	unsigned char *d;
	const unsigned char *s;

	d = dst;
	s = src;
	ctl = -ctl;
	while (len -- > 0) {
		uint32_t x, y;

		x = *s ++;
		y = *d;
		*d = (unsigned char)(y ^ (ctl & (x ^ y)));
		d ++;
	}
}

#define CCOPY   ccopy

static uint32_t
le8_to_le13(uint32_t *dst, const unsigned char *src, size_t len)
{
	uint32_t acc;
	int acc_len;

	acc = 0;
	acc_len = 0;
	while (len -- > 0) {
		acc |= (uint32_t)(*src ++) << acc_len;
		acc_len += 8;
		if (acc_len >= 13) {
			*dst ++ = acc & 0x1FFF;
			acc >>= 13;
			acc_len -= 13;
		}
	}
	return acc;
}

static void
le13_to_le8(unsigned char *dst, size_t len, const uint32_t *src)
{
	uint32_t acc;
	int acc_len;

	acc = 0;
	acc_len = 0;
	while (len -- > 0) {
		if (acc_len < 8) {
			acc |= (*src ++) << acc_len;
			acc_len += 13;
		}
		*dst ++ = (unsigned char)acc;
		acc >>= 8;
		acc_len -= 8;
	}
}

static inline uint32_t
norm13(uint32_t *d, const uint32_t *w, size_t len)
{
	size_t u;
	uint32_t cc;

	cc = 0;
	for (u = 0; u < len; u ++) {
		int32_t z;

		z = w[u] + cc;
		d[u] = z & 0x1FFF;
		cc = ARSH(z, 13);
	}
	return cc;
}


static void
mul20(uint32_t *d, const uint32_t *a, const uint32_t *b)
{
	uint32_t t[39];

	t[ 0] = MUL15(a[ 0], b[ 0]);
	t[ 1] = MUL15(a[ 0], b[ 1])
		+ MUL15(a[ 1], b[ 0]);
	t[ 2] = MUL15(a[ 0], b[ 2])
		+ MUL15(a[ 1], b[ 1])
		+ MUL15(a[ 2], b[ 0]);
	t[ 3] = MUL15(a[ 0], b[ 3])
		+ MUL15(a[ 1], b[ 2])
		+ MUL15(a[ 2], b[ 1])
		+ MUL15(a[ 3], b[ 0]);
	t[ 4] = MUL15(a[ 0], b[ 4])
		+ MUL15(a[ 1], b[ 3])
		+ MUL15(a[ 2], b[ 2])
		+ MUL15(a[ 3], b[ 1])
		+ MUL15(a[ 4], b[ 0]);
	t[ 5] = MUL15(a[ 0], b[ 5])
		+ MUL15(a[ 1], b[ 4])
		+ MUL15(a[ 2], b[ 3])
		+ MUL15(a[ 3], b[ 2])
		+ MUL15(a[ 4], b[ 1])
		+ MUL15(a[ 5], b[ 0]);
	t[ 6] = MUL15(a[ 0], b[ 6])
		+ MUL15(a[ 1], b[ 5])
		+ MUL15(a[ 2], b[ 4])
		+ MUL15(a[ 3], b[ 3])
		+ MUL15(a[ 4], b[ 2])
		+ MUL15(a[ 5], b[ 1])
		+ MUL15(a[ 6], b[ 0]);
	t[ 7] = MUL15(a[ 0], b[ 7])
		+ MUL15(a[ 1], b[ 6])
		+ MUL15(a[ 2], b[ 5])
		+ MUL15(a[ 3], b[ 4])
		+ MUL15(a[ 4], b[ 3])
		+ MUL15(a[ 5], b[ 2])
		+ MUL15(a[ 6], b[ 1])
		+ MUL15(a[ 7], b[ 0]);
	t[ 8] = MUL15(a[ 0], b[ 8])
		+ MUL15(a[ 1], b[ 7])
		+ MUL15(a[ 2], b[ 6])
		+ MUL15(a[ 3], b[ 5])
		+ MUL15(a[ 4], b[ 4])
		+ MUL15(a[ 5], b[ 3])
		+ MUL15(a[ 6], b[ 2])
		+ MUL15(a[ 7], b[ 1])
		+ MUL15(a[ 8], b[ 0]);
	t[ 9] = MUL15(a[ 0], b[ 9])
		+ MUL15(a[ 1], b[ 8])
		+ MUL15(a[ 2], b[ 7])
		+ MUL15(a[ 3], b[ 6])
		+ MUL15(a[ 4], b[ 5])
		+ MUL15(a[ 5], b[ 4])
		+ MUL15(a[ 6], b[ 3])
		+ MUL15(a[ 7], b[ 2])
		+ MUL15(a[ 8], b[ 1])
		+ MUL15(a[ 9], b[ 0]);
	t[10] = MUL15(a[ 0], b[10])
		+ MUL15(a[ 1], b[ 9])
		+ MUL15(a[ 2], b[ 8])
		+ MUL15(a[ 3], b[ 7])
		+ MUL15(a[ 4], b[ 6])
		+ MUL15(a[ 5], b[ 5])
		+ MUL15(a[ 6], b[ 4])
		+ MUL15(a[ 7], b[ 3])
		+ MUL15(a[ 8], b[ 2])
		+ MUL15(a[ 9], b[ 1])
		+ MUL15(a[10], b[ 0]);
	t[11] = MUL15(a[ 0], b[11])
		+ MUL15(a[ 1], b[10])
		+ MUL15(a[ 2], b[ 9])
		+ MUL15(a[ 3], b[ 8])
		+ MUL15(a[ 4], b[ 7])
		+ MUL15(a[ 5], b[ 6])
		+ MUL15(a[ 6], b[ 5])
		+ MUL15(a[ 7], b[ 4])
		+ MUL15(a[ 8], b[ 3])
		+ MUL15(a[ 9], b[ 2])
		+ MUL15(a[10], b[ 1])
		+ MUL15(a[11], b[ 0]);
	t[12] = MUL15(a[ 0], b[12])
		+ MUL15(a[ 1], b[11])
		+ MUL15(a[ 2], b[10])
		+ MUL15(a[ 3], b[ 9])
		+ MUL15(a[ 4], b[ 8])
		+ MUL15(a[ 5], b[ 7])
		+ MUL15(a[ 6], b[ 6])
		+ MUL15(a[ 7], b[ 5])
		+ MUL15(a[ 8], b[ 4])
		+ MUL15(a[ 9], b[ 3])
		+ MUL15(a[10], b[ 2])
		+ MUL15(a[11], b[ 1])
		+ MUL15(a[12], b[ 0]);
	t[13] = MUL15(a[ 0], b[13])
		+ MUL15(a[ 1], b[12])
		+ MUL15(a[ 2], b[11])
		+ MUL15(a[ 3], b[10])
		+ MUL15(a[ 4], b[ 9])
		+ MUL15(a[ 5], b[ 8])
		+ MUL15(a[ 6], b[ 7])
		+ MUL15(a[ 7], b[ 6])
		+ MUL15(a[ 8], b[ 5])
		+ MUL15(a[ 9], b[ 4])
		+ MUL15(a[10], b[ 3])
		+ MUL15(a[11], b[ 2])
		+ MUL15(a[12], b[ 1])
		+ MUL15(a[13], b[ 0]);
	t[14] = MUL15(a[ 0], b[14])
		+ MUL15(a[ 1], b[13])
		+ MUL15(a[ 2], b[12])
		+ MUL15(a[ 3], b[11])
		+ MUL15(a[ 4], b[10])
		+ MUL15(a[ 5], b[ 9])
		+ MUL15(a[ 6], b[ 8])
		+ MUL15(a[ 7], b[ 7])
		+ MUL15(a[ 8], b[ 6])
		+ MUL15(a[ 9], b[ 5])
		+ MUL15(a[10], b[ 4])
		+ MUL15(a[11], b[ 3])
		+ MUL15(a[12], b[ 2])
		+ MUL15(a[13], b[ 1])
		+ MUL15(a[14], b[ 0]);
	t[15] = MUL15(a[ 0], b[15])
		+ MUL15(a[ 1], b[14])
		+ MUL15(a[ 2], b[13])
		+ MUL15(a[ 3], b[12])
		+ MUL15(a[ 4], b[11])
		+ MUL15(a[ 5], b[10])
		+ MUL15(a[ 6], b[ 9])
		+ MUL15(a[ 7], b[ 8])
		+ MUL15(a[ 8], b[ 7])
		+ MUL15(a[ 9], b[ 6])
		+ MUL15(a[10], b[ 5])
		+ MUL15(a[11], b[ 4])
		+ MUL15(a[12], b[ 3])
		+ MUL15(a[13], b[ 2])
		+ MUL15(a[14], b[ 1])
		+ MUL15(a[15], b[ 0]);
	t[16] = MUL15(a[ 0], b[16])
		+ MUL15(a[ 1], b[15])
		+ MUL15(a[ 2], b[14])
		+ MUL15(a[ 3], b[13])
		+ MUL15(a[ 4], b[12])
		+ MUL15(a[ 5], b[11])
		+ MUL15(a[ 6], b[10])
		+ MUL15(a[ 7], b[ 9])
		+ MUL15(a[ 8], b[ 8])
		+ MUL15(a[ 9], b[ 7])
		+ MUL15(a[10], b[ 6])
		+ MUL15(a[11], b[ 5])
		+ MUL15(a[12], b[ 4])
		+ MUL15(a[13], b[ 3])
		+ MUL15(a[14], b[ 2])
		+ MUL15(a[15], b[ 1])
		+ MUL15(a[16], b[ 0]);
	t[17] = MUL15(a[ 0], b[17])
		+ MUL15(a[ 1], b[16])
		+ MUL15(a[ 2], b[15])
		+ MUL15(a[ 3], b[14])
		+ MUL15(a[ 4], b[13])
		+ MUL15(a[ 5], b[12])
		+ MUL15(a[ 6], b[11])
		+ MUL15(a[ 7], b[10])
		+ MUL15(a[ 8], b[ 9])
		+ MUL15(a[ 9], b[ 8])
		+ MUL15(a[10], b[ 7])
		+ MUL15(a[11], b[ 6])
		+ MUL15(a[12], b[ 5])
		+ MUL15(a[13], b[ 4])
		+ MUL15(a[14], b[ 3])
		+ MUL15(a[15], b[ 2])
		+ MUL15(a[16], b[ 1])
		+ MUL15(a[17], b[ 0]);
	t[18] = MUL15(a[ 0], b[18])
		+ MUL15(a[ 1], b[17])
		+ MUL15(a[ 2], b[16])
		+ MUL15(a[ 3], b[15])
		+ MUL15(a[ 4], b[14])
		+ MUL15(a[ 5], b[13])
		+ MUL15(a[ 6], b[12])
		+ MUL15(a[ 7], b[11])
		+ MUL15(a[ 8], b[10])
		+ MUL15(a[ 9], b[ 9])
		+ MUL15(a[10], b[ 8])
		+ MUL15(a[11], b[ 7])
		+ MUL15(a[12], b[ 6])
		+ MUL15(a[13], b[ 5])
		+ MUL15(a[14], b[ 4])
		+ MUL15(a[15], b[ 3])
		+ MUL15(a[16], b[ 2])
		+ MUL15(a[17], b[ 1])
		+ MUL15(a[18], b[ 0]);
	t[19] = MUL15(a[ 0], b[19])
		+ MUL15(a[ 1], b[18])
		+ MUL15(a[ 2], b[17])
		+ MUL15(a[ 3], b[16])
		+ MUL15(a[ 4], b[15])
		+ MUL15(a[ 5], b[14])
		+ MUL15(a[ 6], b[13])
		+ MUL15(a[ 7], b[12])
		+ MUL15(a[ 8], b[11])
		+ MUL15(a[ 9], b[10])
		+ MUL15(a[10], b[ 9])
		+ MUL15(a[11], b[ 8])
		+ MUL15(a[12], b[ 7])
		+ MUL15(a[13], b[ 6])
		+ MUL15(a[14], b[ 5])
		+ MUL15(a[15], b[ 4])
		+ MUL15(a[16], b[ 3])
		+ MUL15(a[17], b[ 2])
		+ MUL15(a[18], b[ 1])
		+ MUL15(a[19], b[ 0]);
	t[20] = MUL15(a[ 1], b[19])
		+ MUL15(a[ 2], b[18])
		+ MUL15(a[ 3], b[17])
		+ MUL15(a[ 4], b[16])
		+ MUL15(a[ 5], b[15])
		+ MUL15(a[ 6], b[14])
		+ MUL15(a[ 7], b[13])
		+ MUL15(a[ 8], b[12])
		+ MUL15(a[ 9], b[11])
		+ MUL15(a[10], b[10])
		+ MUL15(a[11], b[ 9])
		+ MUL15(a[12], b[ 8])
		+ MUL15(a[13], b[ 7])
		+ MUL15(a[14], b[ 6])
		+ MUL15(a[15], b[ 5])
		+ MUL15(a[16], b[ 4])
		+ MUL15(a[17], b[ 3])
		+ MUL15(a[18], b[ 2])
		+ MUL15(a[19], b[ 1]);
	t[21] = MUL15(a[ 2], b[19])
		+ MUL15(a[ 3], b[18])
		+ MUL15(a[ 4], b[17])
		+ MUL15(a[ 5], b[16])
		+ MUL15(a[ 6], b[15])
		+ MUL15(a[ 7], b[14])
		+ MUL15(a[ 8], b[13])
		+ MUL15(a[ 9], b[12])
		+ MUL15(a[10], b[11])
		+ MUL15(a[11], b[10])
		+ MUL15(a[12], b[ 9])
		+ MUL15(a[13], b[ 8])
		+ MUL15(a[14], b[ 7])
		+ MUL15(a[15], b[ 6])
		+ MUL15(a[16], b[ 5])
		+ MUL15(a[17], b[ 4])
		+ MUL15(a[18], b[ 3])
		+ MUL15(a[19], b[ 2]);
	t[22] = MUL15(a[ 3], b[19])
		+ MUL15(a[ 4], b[18])
		+ MUL15(a[ 5], b[17])
		+ MUL15(a[ 6], b[16])
		+ MUL15(a[ 7], b[15])
		+ MUL15(a[ 8], b[14])
		+ MUL15(a[ 9], b[13])
		+ MUL15(a[10], b[12])
		+ MUL15(a[11], b[11])
		+ MUL15(a[12], b[10])
		+ MUL15(a[13], b[ 9])
		+ MUL15(a[14], b[ 8])
		+ MUL15(a[15], b[ 7])
		+ MUL15(a[16], b[ 6])
		+ MUL15(a[17], b[ 5])
		+ MUL15(a[18], b[ 4])
		+ MUL15(a[19], b[ 3]);
	t[23] = MUL15(a[ 4], b[19])
		+ MUL15(a[ 5], b[18])
		+ MUL15(a[ 6], b[17])
		+ MUL15(a[ 7], b[16])
		+ MUL15(a[ 8], b[15])
		+ MUL15(a[ 9], b[14])
		+ MUL15(a[10], b[13])
		+ MUL15(a[11], b[12])
		+ MUL15(a[12], b[11])
		+ MUL15(a[13], b[10])
		+ MUL15(a[14], b[ 9])
		+ MUL15(a[15], b[ 8])
		+ MUL15(a[16], b[ 7])
		+ MUL15(a[17], b[ 6])
		+ MUL15(a[18], b[ 5])
		+ MUL15(a[19], b[ 4]);
	t[24] = MUL15(a[ 5], b[19])
		+ MUL15(a[ 6], b[18])
		+ MUL15(a[ 7], b[17])
		+ MUL15(a[ 8], b[16])
		+ MUL15(a[ 9], b[15])
		+ MUL15(a[10], b[14])
		+ MUL15(a[11], b[13])
		+ MUL15(a[12], b[12])
		+ MUL15(a[13], b[11])
		+ MUL15(a[14], b[10])
		+ MUL15(a[15], b[ 9])
		+ MUL15(a[16], b[ 8])
		+ MUL15(a[17], b[ 7])
		+ MUL15(a[18], b[ 6])
		+ MUL15(a[19], b[ 5]);
	t[25] = MUL15(a[ 6], b[19])
		+ MUL15(a[ 7], b[18])
		+ MUL15(a[ 8], b[17])
		+ MUL15(a[ 9], b[16])
		+ MUL15(a[10], b[15])
		+ MUL15(a[11], b[14])
		+ MUL15(a[12], b[13])
		+ MUL15(a[13], b[12])
		+ MUL15(a[14], b[11])
		+ MUL15(a[15], b[10])
		+ MUL15(a[16], b[ 9])
		+ MUL15(a[17], b[ 8])
		+ MUL15(a[18], b[ 7])
		+ MUL15(a[19], b[ 6]);
	t[26] = MUL15(a[ 7], b[19])
		+ MUL15(a[ 8], b[18])
		+ MUL15(a[ 9], b[17])
		+ MUL15(a[10], b[16])
		+ MUL15(a[11], b[15])
		+ MUL15(a[12], b[14])
		+ MUL15(a[13], b[13])
		+ MUL15(a[14], b[12])
		+ MUL15(a[15], b[11])
		+ MUL15(a[16], b[10])
		+ MUL15(a[17], b[ 9])
		+ MUL15(a[18], b[ 8])
		+ MUL15(a[19], b[ 7]);
	t[27] = MUL15(a[ 8], b[19])
		+ MUL15(a[ 9], b[18])
		+ MUL15(a[10], b[17])
		+ MUL15(a[11], b[16])
		+ MUL15(a[12], b[15])
		+ MUL15(a[13], b[14])
		+ MUL15(a[14], b[13])
		+ MUL15(a[15], b[12])
		+ MUL15(a[16], b[11])
		+ MUL15(a[17], b[10])
		+ MUL15(a[18], b[ 9])
		+ MUL15(a[19], b[ 8]);
	t[28] = MUL15(a[ 9], b[19])
		+ MUL15(a[10], b[18])
		+ MUL15(a[11], b[17])
		+ MUL15(a[12], b[16])
		+ MUL15(a[13], b[15])
		+ MUL15(a[14], b[14])
		+ MUL15(a[15], b[13])
		+ MUL15(a[16], b[12])
		+ MUL15(a[17], b[11])
		+ MUL15(a[18], b[10])
		+ MUL15(a[19], b[ 9]);
	t[29] = MUL15(a[10], b[19])
		+ MUL15(a[11], b[18])
		+ MUL15(a[12], b[17])
		+ MUL15(a[13], b[16])
		+ MUL15(a[14], b[15])
		+ MUL15(a[15], b[14])
		+ MUL15(a[16], b[13])
		+ MUL15(a[17], b[12])
		+ MUL15(a[18], b[11])
		+ MUL15(a[19], b[10]);
	t[30] = MUL15(a[11], b[19])
		+ MUL15(a[12], b[18])
		+ MUL15(a[13], b[17])
		+ MUL15(a[14], b[16])
		+ MUL15(a[15], b[15])
		+ MUL15(a[16], b[14])
		+ MUL15(a[17], b[13])
		+ MUL15(a[18], b[12])
		+ MUL15(a[19], b[11]);
	t[31] = MUL15(a[12], b[19])
		+ MUL15(a[13], b[18])
		+ MUL15(a[14], b[17])
		+ MUL15(a[15], b[16])
		+ MUL15(a[16], b[15])
		+ MUL15(a[17], b[14])
		+ MUL15(a[18], b[13])
		+ MUL15(a[19], b[12]);
	t[32] = MUL15(a[13], b[19])
		+ MUL15(a[14], b[18])
		+ MUL15(a[15], b[17])
		+ MUL15(a[16], b[16])
		+ MUL15(a[17], b[15])
		+ MUL15(a[18], b[14])
		+ MUL15(a[19], b[13]);
	t[33] = MUL15(a[14], b[19])
		+ MUL15(a[15], b[18])
		+ MUL15(a[16], b[17])
		+ MUL15(a[17], b[16])
		+ MUL15(a[18], b[15])
		+ MUL15(a[19], b[14]);
	t[34] = MUL15(a[15], b[19])
		+ MUL15(a[16], b[18])
		+ MUL15(a[17], b[17])
		+ MUL15(a[18], b[16])
		+ MUL15(a[19], b[15]);
	t[35] = MUL15(a[16], b[19])
		+ MUL15(a[17], b[18])
		+ MUL15(a[18], b[17])
		+ MUL15(a[19], b[16]);
	t[36] = MUL15(a[17], b[19])
		+ MUL15(a[18], b[18])
		+ MUL15(a[19], b[17]);
	t[37] = MUL15(a[18], b[19])
		+ MUL15(a[19], b[18]);
	t[38] = MUL15(a[19], b[19]);

	d[39] = norm13(d, t, 39);
}

static void
square20(uint32_t *d, const uint32_t *a)
{
	uint32_t t[39];

	t[ 0] = MUL15(a[ 0], a[ 0]);
	t[ 1] = ((MUL15(a[ 0], a[ 1])) << 1);
	t[ 2] = MUL15(a[ 1], a[ 1])
		+ ((MUL15(a[ 0], a[ 2])) << 1);
	t[ 3] = ((MUL15(a[ 0], a[ 3])
		+ MUL15(a[ 1], a[ 2])) << 1);
	t[ 4] = MUL15(a[ 2], a[ 2])
		+ ((MUL15(a[ 0], a[ 4])
		+ MUL15(a[ 1], a[ 3])) << 1);
	t[ 5] = ((MUL15(a[ 0], a[ 5])
		+ MUL15(a[ 1], a[ 4])
		+ MUL15(a[ 2], a[ 3])) << 1);
	t[ 6] = MUL15(a[ 3], a[ 3])
		+ ((MUL15(a[ 0], a[ 6])
		+ MUL15(a[ 1], a[ 5])
		+ MUL15(a[ 2], a[ 4])) << 1);
	t[ 7] = ((MUL15(a[ 0], a[ 7])
		+ MUL15(a[ 1], a[ 6])
		+ MUL15(a[ 2], a[ 5])
		+ MUL15(a[ 3], a[ 4])) << 1);
	t[ 8] = MUL15(a[ 4], a[ 4])
		+ ((MUL15(a[ 0], a[ 8])
		+ MUL15(a[ 1], a[ 7])
		+ MUL15(a[ 2], a[ 6])
		+ MUL15(a[ 3], a[ 5])) << 1);
	t[ 9] = ((MUL15(a[ 0], a[ 9])
		+ MUL15(a[ 1], a[ 8])
		+ MUL15(a[ 2], a[ 7])
		+ MUL15(a[ 3], a[ 6])
		+ MUL15(a[ 4], a[ 5])) << 1);
	t[10] = MUL15(a[ 5], a[ 5])
		+ ((MUL15(a[ 0], a[10])
		+ MUL15(a[ 1], a[ 9])
		+ MUL15(a[ 2], a[ 8])
		+ MUL15(a[ 3], a[ 7])
		+ MUL15(a[ 4], a[ 6])) << 1);
	t[11] = ((MUL15(a[ 0], a[11])
		+ MUL15(a[ 1], a[10])
		+ MUL15(a[ 2], a[ 9])
		+ MUL15(a[ 3], a[ 8])
		+ MUL15(a[ 4], a[ 7])
		+ MUL15(a[ 5], a[ 6])) << 1);
	t[12] = MUL15(a[ 6], a[ 6])
		+ ((MUL15(a[ 0], a[12])
		+ MUL15(a[ 1], a[11])
		+ MUL15(a[ 2], a[10])
		+ MUL15(a[ 3], a[ 9])
		+ MUL15(a[ 4], a[ 8])
		+ MUL15(a[ 5], a[ 7])) << 1);
	t[13] = ((MUL15(a[ 0], a[13])
		+ MUL15(a[ 1], a[12])
		+ MUL15(a[ 2], a[11])
		+ MUL15(a[ 3], a[10])
		+ MUL15(a[ 4], a[ 9])
		+ MUL15(a[ 5], a[ 8])
		+ MUL15(a[ 6], a[ 7])) << 1);
	t[14] = MUL15(a[ 7], a[ 7])
		+ ((MUL15(a[ 0], a[14])
		+ MUL15(a[ 1], a[13])
		+ MUL15(a[ 2], a[12])
		+ MUL15(a[ 3], a[11])
		+ MUL15(a[ 4], a[10])
		+ MUL15(a[ 5], a[ 9])
		+ MUL15(a[ 6], a[ 8])) << 1);
	t[15] = ((MUL15(a[ 0], a[15])
		+ MUL15(a[ 1], a[14])
		+ MUL15(a[ 2], a[13])
		+ MUL15(a[ 3], a[12])
		+ MUL15(a[ 4], a[11])
		+ MUL15(a[ 5], a[10])
		+ MUL15(a[ 6], a[ 9])
		+ MUL15(a[ 7], a[ 8])) << 1);
	t[16] = MUL15(a[ 8], a[ 8])
		+ ((MUL15(a[ 0], a[16])
		+ MUL15(a[ 1], a[15])
		+ MUL15(a[ 2], a[14])
		+ MUL15(a[ 3], a[13])
		+ MUL15(a[ 4], a[12])
		+ MUL15(a[ 5], a[11])
		+ MUL15(a[ 6], a[10])
		+ MUL15(a[ 7], a[ 9])) << 1);
	t[17] = ((MUL15(a[ 0], a[17])
		+ MUL15(a[ 1], a[16])
		+ MUL15(a[ 2], a[15])
		+ MUL15(a[ 3], a[14])
		+ MUL15(a[ 4], a[13])
		+ MUL15(a[ 5], a[12])
		+ MUL15(a[ 6], a[11])
		+ MUL15(a[ 7], a[10])
		+ MUL15(a[ 8], a[ 9])) << 1);
	t[18] = MUL15(a[ 9], a[ 9])
		+ ((MUL15(a[ 0], a[18])
		+ MUL15(a[ 1], a[17])
		+ MUL15(a[ 2], a[16])
		+ MUL15(a[ 3], a[15])
		+ MUL15(a[ 4], a[14])
		+ MUL15(a[ 5], a[13])
		+ MUL15(a[ 6], a[12])
		+ MUL15(a[ 7], a[11])
		+ MUL15(a[ 8], a[10])) << 1);
	t[19] = ((MUL15(a[ 0], a[19])
		+ MUL15(a[ 1], a[18])
		+ MUL15(a[ 2], a[17])
		+ MUL15(a[ 3], a[16])
		+ MUL15(a[ 4], a[15])
		+ MUL15(a[ 5], a[14])
		+ MUL15(a[ 6], a[13])
		+ MUL15(a[ 7], a[12])
		+ MUL15(a[ 8], a[11])
		+ MUL15(a[ 9], a[10])) << 1);
	t[20] = MUL15(a[10], a[10])
		+ ((MUL15(a[ 1], a[19])
		+ MUL15(a[ 2], a[18])
		+ MUL15(a[ 3], a[17])
		+ MUL15(a[ 4], a[16])
		+ MUL15(a[ 5], a[15])
		+ MUL15(a[ 6], a[14])
		+ MUL15(a[ 7], a[13])
		+ MUL15(a[ 8], a[12])
		+ MUL15(a[ 9], a[11])) << 1);
	t[21] = ((MUL15(a[ 2], a[19])
		+ MUL15(a[ 3], a[18])
		+ MUL15(a[ 4], a[17])
		+ MUL15(a[ 5], a[16])
		+ MUL15(a[ 6], a[15])
		+ MUL15(a[ 7], a[14])
		+ MUL15(a[ 8], a[13])
		+ MUL15(a[ 9], a[12])
		+ MUL15(a[10], a[11])) << 1);
	t[22] = MUL15(a[11], a[11])
		+ ((MUL15(a[ 3], a[19])
		+ MUL15(a[ 4], a[18])
		+ MUL15(a[ 5], a[17])
		+ MUL15(a[ 6], a[16])
		+ MUL15(a[ 7], a[15])
		+ MUL15(a[ 8], a[14])
		+ MUL15(a[ 9], a[13])
		+ MUL15(a[10], a[12])) << 1);
	t[23] = ((MUL15(a[ 4], a[19])
		+ MUL15(a[ 5], a[18])
		+ MUL15(a[ 6], a[17])
		+ MUL15(a[ 7], a[16])
		+ MUL15(a[ 8], a[15])
		+ MUL15(a[ 9], a[14])
		+ MUL15(a[10], a[13])
		+ MUL15(a[11], a[12])) << 1);
	t[24] = MUL15(a[12], a[12])
		+ ((MUL15(a[ 5], a[19])
		+ MUL15(a[ 6], a[18])
		+ MUL15(a[ 7], a[17])
		+ MUL15(a[ 8], a[16])
		+ MUL15(a[ 9], a[15])
		+ MUL15(a[10], a[14])
		+ MUL15(a[11], a[13])) << 1);
	t[25] = ((MUL15(a[ 6], a[19])
		+ MUL15(a[ 7], a[18])
		+ MUL15(a[ 8], a[17])
		+ MUL15(a[ 9], a[16])
		+ MUL15(a[10], a[15])
		+ MUL15(a[11], a[14])
		+ MUL15(a[12], a[13])) << 1);
	t[26] = MUL15(a[13], a[13])
		+ ((MUL15(a[ 7], a[19])
		+ MUL15(a[ 8], a[18])
		+ MUL15(a[ 9], a[17])
		+ MUL15(a[10], a[16])
		+ MUL15(a[11], a[15])
		+ MUL15(a[12], a[14])) << 1);
	t[27] = ((MUL15(a[ 8], a[19])
		+ MUL15(a[ 9], a[18])
		+ MUL15(a[10], a[17])
		+ MUL15(a[11], a[16])
		+ MUL15(a[12], a[15])
		+ MUL15(a[13], a[14])) << 1);
	t[28] = MUL15(a[14], a[14])
		+ ((MUL15(a[ 9], a[19])
		+ MUL15(a[10], a[18])
		+ MUL15(a[11], a[17])
		+ MUL15(a[12], a[16])
		+ MUL15(a[13], a[15])) << 1);
	t[29] = ((MUL15(a[10], a[19])
		+ MUL15(a[11], a[18])
		+ MUL15(a[12], a[17])
		+ MUL15(a[13], a[16])
		+ MUL15(a[14], a[15])) << 1);
	t[30] = MUL15(a[15], a[15])
		+ ((MUL15(a[11], a[19])
		+ MUL15(a[12], a[18])
		+ MUL15(a[13], a[17])
		+ MUL15(a[14], a[16])) << 1);
	t[31] = ((MUL15(a[12], a[19])
		+ MUL15(a[13], a[18])
		+ MUL15(a[14], a[17])
		+ MUL15(a[15], a[16])) << 1);
	t[32] = MUL15(a[16], a[16])
		+ ((MUL15(a[13], a[19])
		+ MUL15(a[14], a[18])
		+ MUL15(a[15], a[17])) << 1);
	t[33] = ((MUL15(a[14], a[19])
		+ MUL15(a[15], a[18])
		+ MUL15(a[16], a[17])) << 1);
	t[34] = MUL15(a[17], a[17])
		+ ((MUL15(a[15], a[19])
		+ MUL15(a[16], a[18])) << 1);
	t[35] = ((MUL15(a[16], a[19])
		+ MUL15(a[17], a[18])) << 1);
	t[36] = MUL15(a[18], a[18])
		+ ((MUL15(a[17], a[19])) << 1);
	t[37] = ((MUL15(a[18], a[19])) << 1);
	t[38] = MUL15(a[19], a[19]);

	d[39] = norm13(d, t, 39);
}


static uint32_t
reduce_final_f255(uint32_t *d)
{
	uint32_t t[20];
	uint32_t cc;
	int i;

	memcpy(t, d, sizeof t);
	cc = 19;
	for (i = 0; i < 20; i ++) {
		uint32_t w;

		w = t[i] + cc;
		cc = w >> 13;
		t[i] = w & 0x1FFF;
	}
	cc = t[19] >> 8;
	t[19] &= 0xFF;
	CCOPY(cc, d, t, sizeof t);
	return cc;
}

static void
f255_mulgen(uint32_t *d, const uint32_t *a, const uint32_t *b, int square)
{
	uint32_t t[40], cc, w;

	/*
	 * Compute raw multiplication. All result words fit in 13 bits
	 * each; upper word (t[39]) must fit on 5 bits, since the product
	 * of two 256-bit integers must fit on 512 bits.
	 */
	if (square) {
		square20(t, a);
	} else {
		mul20(t, a, b);
	}

	/*
	 * Modular reduction: each high word is added where necessary.
	 * Since the modulus is 2^255-19 and word 20 corresponds to
	 * offset 20*13 = 260, word 20+k must be added to word k with
	 * a factor of 19*2^5 = 608. The extra bits in word 19 are also
	 * added that way.
	 */
	cc = MUL15(t[19] >> 8, 19);
	t[19] &= 0xFF;

#define MM1(x)   do { \
		w = t[x] + cc + MUL15(t[(x) + 20], 608); \
		t[x] = w & 0x1FFF; \
		cc = w >> 13; \
	} while (0)

	MM1( 0);
	MM1( 1);
	MM1( 2);
	MM1( 3);
	MM1( 4);
	MM1( 5);
	MM1( 6);
	MM1( 7);
	MM1( 8);
	MM1( 9);
	MM1(10);
	MM1(11);
	MM1(12);
	MM1(13);
	MM1(14);
	MM1(15);
	MM1(16);
	MM1(17);
	MM1(18);
	MM1(19);

#undef MM1

	cc = MUL15(w >> 8, 19);
	t[19] &= 0xFF;

#define MM2(x)   do { \
		w = t[x] + cc; \
		d[x] = w & 0x1FFF; \
		cc = w >> 13; \
	} while (0)

	MM2( 0);
	MM2( 1);
	MM2( 2);
	MM2( 3);
	MM2( 4);
	MM2( 5);
	MM2( 6);
	MM2( 7);
	MM2( 8);
	MM2( 9);
	MM2(10);
	MM2(11);
	MM2(12);
	MM2(13);
	MM2(14);
	MM2(15);
	MM2(16);
	MM2(17);
	MM2(18);
	MM2(19);

#undef MM2
}

#define f255_mul(d, a, b)   f255_mulgen(d, a, b, 0)
#define f255_square(d, a)   f255_mulgen(d, a, a, 1)

static void
f255_add(uint32_t *d, const uint32_t *a, const uint32_t *b)
{
	int i;
	uint32_t cc, w;

	cc = 0;
	for (i = 0; i < 20; i ++) {
		w = a[i] + b[i] + cc;
		d[i] = w & 0x1FFF;
		cc = w >> 13;
	}
	cc = MUL15(w >> 8, 19);
	d[19] &= 0xFF;
	for (i = 0; i < 20; i ++) {
		w = d[i] + cc;
		d[i] = w & 0x1FFF;
		cc = w >> 13;
	}
}

static void
f255_sub(uint32_t *d, const uint32_t *a, const uint32_t *b)
{
	/*
	 * We actually compute a - b + 2*p, so that the final value is
	 * necessarily positive.
	 */
	int i;
	uint32_t cc, w;

	cc = (uint32_t)-38;
	for (i = 0; i < 20; i ++) {
		w = a[i] - b[i] + cc;
		d[i] = w & 0x1FFF;
		cc = ARSH(w, 13);
	}
	cc = MUL15((w + 0x200) >> 8, 19);
	d[19] &= 0xFF;
	for (i = 0; i < 20; i ++) {
		w = d[i] + cc;
		d[i] = w & 0x1FFF;
		cc = w >> 13;
	}
}

static void
f255_mul_a24(uint32_t *d, const uint32_t *a)
{
	int i;
	uint32_t cc, w;

	cc = 0;
	for (i = 0; i < 20; i ++) {
		w = MUL15(a[i], 121665) + cc;
		d[i] = w & 0x1FFF;
		cc = w >> 13;
	}
	cc = MUL15(w >> 8, 19);
	d[19] &= 0xFF;
	for (i = 0; i < 20; i ++) {
		w = d[i] + cc;
		d[i] = w & 0x1FFF;
		cc = w >> 13;
	}
}

static void
cswap(uint32_t *a, uint32_t *b, uint32_t ctl)
{
	int i;

	ctl = -ctl;
	for (i = 0; i < 20; i ++) {
		uint32_t aw, bw, tw;

		aw = a[i];
		bw = b[i];
		tw = ctl & (aw ^ bw);
		a[i] = aw ^ tw;
		b[i] = bw ^ tw;
	}
}

/*
 * Inverse of a by exponentiation (p - 2), as in BearSSL; d and t are
 * scratch of 20 words each, a must not alias d.
 */
static void
f255_invert(uint32_t *d, const uint32_t *a, uint32_t *t)
{
	int i;

	memcpy(t, a, 20 * sizeof(uint32_t));
	for (i = 0; i < 15; i ++) {
		SODIUM_ESP8266_YIELD();
		f255_square(t, t);
		f255_mul(t, t, a);
	}
	memcpy(d, t, 20 * sizeof(uint32_t));
	for (i = 0; i < 14; i ++) {
		int j;

		SODIUM_ESP8266_YIELD();
		for (j = 0; j < 16; j ++) {
			f255_square(d, d);
		}
		f255_mul(d, d, t);
	}
	for (i = 14; i >= 0; i --) {
		f255_square(d, d);
		if ((0xFFEB >> i) & 1) {
			f255_mul(d, a, d);
		}
	}
}

int
sodium_esphome_x25519_m15(unsigned char *q, const unsigned char *n,
                          const unsigned char *p)
{
	/* One block so the scalar-derived state can be wiped in one call */
	struct {
		uint32_t x1[20], x2[20], z2[20], x3[20], z3[20];
		uint32_t t1[20], t2[20], t3[20], t4[20];
	} w;
	uint32_t *x1 = w.x1, *x2 = w.x2, *z2 = w.z2, *x3 = w.x3, *z3 = w.z3;
	uint32_t *t1 = w.t1, *t2 = w.t2, *t3 = w.t3, *t4 = w.t4;
	uint32_t swap;
	int i;

	/* Bit 255 of the u coordinate is ignored; it lands in bit 8 of word 19 */
	x1[19] = le8_to_le13(x1, p, 32) & 0xFF;
	memcpy(x3, x1, sizeof w.x1);
	memset(z2, 0, sizeof w.z2);
	memset(x2, 0, sizeof w.x2);
	x2[0] = 1;
	memset(z3, 0, sizeof w.z3);
	z3[0] = 1;

	/*
	 * Montgomery ladder. Same step as BearSSL's api_mul(), with the nine
	 * per-step temporaries folded into four: t1 = a then aa, t2 = b then
	 * bb then e, t3 = c then cb, t4 = d then da. The scalar is clamped on
	 * the fly (bits 0 to 2 cleared, bit 254 set, bit 255 never visited)
	 * so no private copy of it is needed; the choice depends only on the
	 * public loop index.
	 */
	swap = 0;
	for (i = 254; i >= 0; i --) {
		uint32_t kt;

		SODIUM_ESP8266_YIELD();
		if (i == 254) {
			kt = 1;
		} else if (i < 3) {
			kt = 0;
		} else {
			kt = (n[i >> 3] >> (i & 7)) & 1;
		}
		swap ^= kt;
		cswap(x2, x3, swap);
		cswap(z2, z3, swap);
		swap = kt;

		f255_add(t1, x2, z2);
		f255_sub(t2, x2, z2);
		f255_add(t3, x3, z3);
		f255_sub(t4, x3, z3);
		f255_mul(t4, t4, t1);
		f255_mul(t3, t3, t2);

		f255_add(x3, t4, t3);
		f255_square(x3, x3);
		f255_sub(z3, t4, t3);
		f255_square(z3, z3);
		f255_mul(z3, z3, x1);

		f255_square(t1, t1);
		f255_square(t2, t2);
		f255_mul(x2, t1, t2);
		f255_sub(t2, t1, t2);
		f255_mul_a24(z2, t2);
		f255_add(z2, z2, t1);
		f255_mul(z2, t2, z2);
	}
	cswap(x2, x3, swap);
	cswap(z2, z3, swap);

	f255_invert(t2, z2, t1);
	f255_mul(x2, x2, t2);
	reduce_final_f255(x2);
	le13_to_le8(q, 32, x2);
	sodium_memzero(&w, sizeof w);
	return 0;
}

/*
 * Base point multiply on the same 13-bit limbs: the ref10 walk over the
 * packed Edwards table of patch 10 (16 windows of 8 points as canonical
 * byte encodings of y+x, y-x and 2dxy), with the point arithmetic written
 * on f255_mul, so the ref10 field code is not linked on these cores. The
 * curve is the twisted Edwards form with a = -1, as ref10 uses, and the
 * result is converted to the Montgomery u coordinate at the end.
 */

#ifdef SODIUM_ESPHOME_ESP8266
#define M15_BASE_ATTR __attribute__((section(".irom.text")))
#else
#define M15_BASE_ATTR
#endif

/* p1p1 -> extended: X = X*T, Y = Y*Z, Z = Z*T, T = X*Y */
static void
ge_m15_p1p1_to_p3(uint32_t *hx, uint32_t *hy, uint32_t *hz, uint32_t *ht,
                  const uint32_t *rx, const uint32_t *ry,
                  const uint32_t *rz, const uint32_t *rt)
{
	f255_mul(hx, rx, rt);
	f255_mul(hy, ry, rz);
	f255_mul(hz, rz, rt);
	f255_mul(ht, rx, ry);
}

/* projective doubling, ref10's ge25519_p2_dbl: (X, Y, Z) -> p1p1 */
static void
ge_m15_p2_dbl(uint32_t *rx, uint32_t *ry, uint32_t *rz, uint32_t *rt,
              const uint32_t *x, const uint32_t *y, const uint32_t *z,
              uint32_t *t0)
{
	f255_square(rx, x);
	f255_square(rz, y);
	f255_square(rt, z);
	f255_add(rt, rt, rt);
	f255_add(ry, x, y);
	f255_square(t0, ry);
	f255_add(ry, rz, rx);
	f255_sub(rz, rz, rx);
	f255_sub(rx, t0, ry);
	f255_sub(rt, rt, rz);
}

/* extended + precomputed (y+x, y-x, 2dxy), ref10's ge25519_madd -> p1p1 */
static void
ge_m15_madd(uint32_t *rx, uint32_t *ry, uint32_t *rz, uint32_t *rt,
            const uint32_t *hx, const uint32_t *hy, const uint32_t *hz,
            const uint32_t *ht, const uint32_t *yplusx,
            const uint32_t *yminusx, const uint32_t *xy2d, uint32_t *t0)
{
	f255_add(rx, hy, hx);
	f255_sub(ry, hy, hx);
	f255_mul(rz, rx, yplusx);
	f255_mul(ry, ry, yminusx);
	f255_mul(rt, xy2d, ht);
	f255_add(t0, hz, hz);
	f255_sub(rx, rz, ry);
	f255_add(ry, rz, ry);
	f255_add(rz, t0, rt);
	f255_sub(rt, t0, rt);
}

/*
 * Constant time select of window pos, entry b in -8..8: the identity for
 * 0, the table point for b > 0, its negation for b < 0. The words are
 * selected first and only the winner is decoded.
 */
static void
ge_m15_select(uint32_t *yplusx, uint32_t *yminusx, uint32_t *xy2d,
              int pos, signed char b, uint32_t *t0)
{
	static const uint32_t M15_BASE_ATTR base_packed[16][8][24] = {
#include "../libsodium/src/libsodium/crypto_core/ed25519/ref10/base_packed.h"
	};
	uint32_t sel[24];
	unsigned char bytes[96];
	uint32_t bneg, babs;
	int i, j;

	bneg = ((uint32_t) (int32_t) b) >> 31;
	babs = (uint32_t) (b - (int) ((0 - bneg) & (uint32_t) b) * 2);
	memset(sel, 0, sizeof sel);
	sel[0] = 1;
	sel[8] = 1;
	for (j = 0; j < 8; j ++) {
		uint32_t mask = 0 - (uint32_t) ((((uint32_t) (babs ^ (uint32_t) (j + 1))) - 1) >> 31);
		const uint32_t *row = base_packed[pos][j];

		for (i = 0; i < 24; i ++) {
			sel[i] ^= mask & (sel[i] ^ row[i]);
		}
	}
	for (i = 0; i < 24; i ++) {
		bytes[4 * i] = (unsigned char) sel[i];
		bytes[4 * i + 1] = (unsigned char) (sel[i] >> 8);
		bytes[4 * i + 2] = (unsigned char) (sel[i] >> 16);
		bytes[4 * i + 3] = (unsigned char) (sel[i] >> 24);
	}
	yplusx[19] = le8_to_le13(yplusx, bytes, 32) & 0xFF;
	yminusx[19] = le8_to_le13(yminusx, bytes + 32, 32) & 0xFF;
	xy2d[19] = le8_to_le13(xy2d, bytes + 64, 32) & 0xFF;
	/* -P: swap y+x and y-x, negate 2dxy */
	cswap(yplusx, yminusx, bneg);
	memset(t0, 0, 20 * sizeof(uint32_t));
	f255_sub(t0, t0, xy2d);
	ccopy(bneg, xy2d, t0, 20 * sizeof(uint32_t));
}

int
sodium_esphome_x25519_m15_base(unsigned char *q, const unsigned char *n)
{
	struct {
		uint32_t hx[20], hy[20], hz[20], ht[20];
		uint32_t rx[20], ry[20], rz[20], rt[20];
		uint32_t px[20], py[20], pz[20];
		uint32_t t0[20], t1[20];
		signed char e[64];
	} w;
	signed char carry;
	int i, pass;

	/* clamped scalar as signed base 16 digits, as ref10 */
	for (i = 0; i < 32; i ++) {
		w.e[2 * i] = (signed char) (n[i] & 15);
		w.e[2 * i + 1] = (signed char) ((n[i] >> 4) & 15);
	}
	w.e[0] &= 8;
	w.e[63] = (signed char) ((w.e[63] & 7) | 4);
	carry = 0;
	for (i = 0; i < 63; i ++) {
		w.e[i] = (signed char) (w.e[i] + carry);
		carry = (signed char) ((w.e[i] + 8) >> 4);
		w.e[i] = (signed char) (w.e[i] - (carry << 4));
	}
	w.e[63] = (signed char) (w.e[63] + carry);

	/* identity in extended coordinates */
	memset(w.hx, 0, sizeof w.hx);
	memset(w.hy, 0, sizeof w.hy);
	memset(w.hz, 0, sizeof w.hz);
	memset(w.ht, 0, sizeof w.ht);
	w.hy[0] = 1;
	w.hz[0] = 1;

	/* the table covers 16^(4k): four passes over i % 4 with four
	   doublings between them, as ref10's walk over the packed table */
	for (pass = 3; pass >= 0; pass --) {
		if (pass != 3) {
			ge_m15_p2_dbl(w.rx, w.ry, w.rz, w.rt, w.hx, w.hy, w.hz, w.t0);
			for (i = 0; i < 3; i ++) {
				f255_mul(w.hx, w.rx, w.rt);
				f255_mul(w.hy, w.ry, w.rz);
				f255_mul(w.hz, w.rz, w.rt);
				ge_m15_p2_dbl(w.rx, w.ry, w.rz, w.rt, w.hx, w.hy, w.hz, w.t0);
			}
			ge_m15_p1p1_to_p3(w.hx, w.hy, w.hz, w.ht, w.rx, w.ry, w.rz, w.rt);
		}
		for (i = pass; i < 64; i += 4) {
			SODIUM_ESP8266_YIELD();
			ge_m15_select(w.px, w.py, w.pz, i / 4, w.e[i], w.t0);
			ge_m15_madd(w.rx, w.ry, w.rz, w.rt, w.hx, w.hy, w.hz, w.ht,
			            w.px, w.py, w.pz, w.t0);
			ge_m15_p1p1_to_p3(w.hx, w.hy, w.hz, w.ht, w.rx, w.ry, w.rz, w.rt);
		}
	}

	/* u = (Z + Y) / (Z - Y) */
	f255_add(w.t0, w.hz, w.hy);
	f255_sub(w.t1, w.hz, w.hy);
	f255_invert(w.px, w.t1, w.py);
	f255_mul(w.t0, w.t0, w.px);
	reduce_final_f255(w.t0);
	le13_to_le8(q, 32, w.t0);
	sodium_memzero(&w, sizeof w);
	return 0;
}
