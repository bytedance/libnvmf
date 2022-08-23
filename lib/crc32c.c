/* taken from internet and modified by helei */
/*
 * crc32c.c -- compute CRC-32C using the Intel crc32 instruction
 * Copyright (C) 2013, 2021 Mark Adler
 * Version 1.1  31 May 2021  Mark Adler
 */

/*
 * This software is provided 'as-is', without any express or implied
 * warranty.  In no event will the author be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software
 *    in a product, an acknowledgment in the product documentation would be
 *    appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
 *
 * Mark Adler
 * madler@alumni.caltech.edu
 */

/*
 * Version History:
 * 1.0  10 Feb 2013  First version
 * 1.1  31 May 2021  Correct register constraints on assembly instructions
 *                   Include pre-computed tables to avoid use of pthreads
 *                   Return zero for the CRC when buf is NULL, as initial value
 */

/*
 * Use hardware CRC instruction on Intel SSE 4.2 processors.  This computes a
 * CRC-32C, *not* the CRC-32 used by Ethernet and zip, gzip, etc.  A software
 * version is provided as a fall-back, as well as for speed comparisons.
 */

#include <stddef.h>
#include <stdint.h>

/*
 * Tables for CRC word-wise calculation, definitions of LONG and SHORT, and CRC
 * shifts by LONG and SHORT bytes.
 */
#include "crc32c.h"

/*
 * Table-driven software version as a fall-back.  This is about 15 times slower
 * than using the hardware instructions.  This assumes little-endian integers,
 * as is the case on Intel processors that the assembler code here is for.
 */
static uint32_t crc32c_sw(uint32_t crc, void const *buf, size_t len)
{
	if (buf == NULL) {
		return 0;
	}
	unsigned char const *data = buf;
	while (len && ((uintptr_t)data & 7) != 0) {
		crc = (crc >> 8) ^ crc32c_table[0][(crc ^ *data++) & 0xff];
		len--;
	}
	size_t n = len >> 3;
	for (size_t i = 0; i < n; i++) {
		uint64_t word = crc ^ ((uint64_t const *)data)[i];
		crc = crc32c_table[7][word & 0xff] ^
			crc32c_table[6][(word >> 8) & 0xff] ^
			crc32c_table[5][(word >> 16) & 0xff] ^
			crc32c_table[4][(word >> 24) & 0xff] ^
			crc32c_table[3][(word >> 32) & 0xff] ^
			crc32c_table[2][(word >> 40) & 0xff] ^
			crc32c_table[1][(word >> 48) & 0xff] ^
			crc32c_table[0][word >> 56];
	}
	data += n << 3;
	len &= 7;
	while (len) {
		len--;
		crc = (crc >> 8) ^ crc32c_table[0][(crc ^ *data++) & 0xff];
	}
	return crc;
}

/* Apply the zeros operator table to crc. */
static uint32_t crc32c_shift(uint32_t zeros[][256], uint32_t crc)
{
	return zeros[0][crc & 0xff] ^ zeros[1][(crc >> 8) & 0xff] ^
		zeros[2][(crc >> 16) & 0xff] ^ zeros[3][crc >> 24];
}

/*
 * Compute CRC-32C using the Intel hardware instruction. Three crc32q
 * instructions are run in parallel on a single core. This gives a
 * factor-of-three speedup over a single crc32q instruction, since the
 * throughput of that instruction is one cycle, but the latency is three
 * cycles.
 */
static uint32_t crc32c_hw(uint32_t crc, void const *buf, size_t len)
{
	if (buf == NULL) {
		return 0;
	}

	/* Pre-process the crc. */
	uint64_t crc0 = crc ^ 0xffffffff;

	/*
	 * Compute the crc for up to seven leading bytes, bringing the data pointer
	 * to an eight-byte boundary.
	 */
	unsigned char const *next = buf;
	while (len && ((uintptr_t)next & 7) != 0) {
		__asm__("crc32b\t" "(%1), %0"
			: "+r"(crc0)
			: "r"(next), "m"(*next));
		next++;
		len--;
	}

	/*
	 * Compute the crc on sets of LONG*3 bytes, making use of three ALUs in
	 * parallel on a single core.
	 */
	while (len >= LONG * 3) {
		uint64_t crc1 = 0;
		uint64_t crc2 = 0;
		unsigned char const *end = next + LONG;
		do {
			__asm__("crc32q\t" "(%3), %0\n\t"
				"crc32q\t" LONGx1 "(%3), %1\n\t"
				"crc32q\t" LONGx2 "(%3), %2"
				: "+r"(crc0), "+r"(crc1), "+r"(crc2)
				: "r"(next), "m"(*next));
			next += 8;
		} while (next < end);
		crc0 = crc32c_shift(crc32c_long, crc0) ^ crc1;
		crc0 = crc32c_shift(crc32c_long, crc0) ^ crc2;
		next += LONG * 2;
		len -= LONG * 3;
	}

	/*
	 * Do the same thing, but now on SHORT*3 blocks for the remaining data less
	 * than a LONG*3 block.
	 */
	while (len >= SHORT * 3) {
		uint64_t crc1 = 0;
		uint64_t crc2 = 0;
		unsigned char const *end = next + SHORT;
		do {
			__asm__("crc32q\t" "(%3), %0\n\t"
				"crc32q\t" SHORTx1 "(%3), %1\n\t"
				"crc32q\t" SHORTx2 "(%3), %2"
				: "+r"(crc0), "+r"(crc1), "+r"(crc2)
				: "r"(next), "m"(*next));
			next += 8;
		} while (next < end);
		crc0 = crc32c_shift(crc32c_short, crc0) ^ crc1;
		crc0 = crc32c_shift(crc32c_short, crc0) ^ crc2;
		next += SHORT * 2;
		len -= SHORT * 3;
	}

	/* Compute the crc on the remaining eight-byte units less than a SHORT*3 block. */
	unsigned char const *end = next + (len - (len & 7));
	while (next < end) {
		__asm__("crc32q\t" "(%1), %0"
			: "+r"(crc0)
			: "r"(next), "m"(*next));
		next += 8;
	}
	len &= 7;

	/* Compute the crc for up to seven trailing bytes. */
	while (len) {
		__asm__("crc32b\t" "(%1), %0"
			: "+r"(crc0)
			: "r"(next), "m"(*next));
		next++;
		len--;
	}

	/* Return the crc, post-processed. */
	return ~(uint32_t)crc0;
}

/*
 * Check for SSE 4.2.  SSE 4.2 was first supported in Nehalem processors
 * introduced in November, 2008.  This does not check for the existence of the
 * cpuid instruction itself, which was introduced on the 486SL in 1992, so this
 * will fail on earlier x86 processors.  cpuid works on all Pentium and later
 * processors.
 */
#define SSE42(have) \
	do { \
		uint32_t eax, ecx; \
		eax = 1; \
		__asm__("cpuid" \
			: "=c"(ecx) \
			: "a"(eax) \
			: "%ebx", "%edx"); \
		(have) = (ecx >> 20) & 1; \
	} while (0)

/*
 * Compute a CRC-32C.  If the crc32 instruction is available, use the hardware
 * version.  Otherwise, use the software version.
 */
uint32_t crc32c(uint32_t crc, void const *buf, size_t len)
{
	int sse42;
	SSE42(sse42);
	return sse42 ? crc32c_hw(crc, buf, len) : crc32c_sw(crc, buf, len);
}
