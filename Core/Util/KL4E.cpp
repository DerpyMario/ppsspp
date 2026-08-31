// SPDX-License-Identifier: GPL-3.0-or-later
//
// KL4E/KL3E decompression, ported from pspdecrypt's kl4e.c:
//   https://github.com/John-K/pspdecrypt  (GPL-3.0)
// reverse engineered from the PSP 6.60 firmware by artart78. The original is
// UtilsForKernel_6C6887EE in sysmem.prx, and artart78 in turn credits BenHur (libLZR) and tpunix
// (kirk_engine's tlzrc.c, which PPSSPP already carries as Core/FileSystems/tlzrc.cpp) for the
// related 2RLZ/LZRC variants that made the format legible.
//
// NOTE: unlike the rest of PPSSPP, which is GPL-2.0-or-later, this file is GPL-3.0-or-later,
// because the implementation it derives from is. Anything linking it is therefore GPL-3.0.
//
// Two deliberate differences from the reference, both about running this on a host CPU with
// untrusted input rather than on a PSP with data Sony signed:
//
//  - The original indexes its probability tables through raw pointers, and derives part of the
//    model from the low bits of *addresses* - `(size_t)curOut & 7`, `(size_t)probPtr & 7`. On the
//    PSP those buffers are aligned, so the low bits are the offset within the buffer, which is the
//    only thing the compressor could have known about. Here everything is an index, so the same
//    numbers come out no matter what the allocator returns. That also removes the out-of-bounds
//    pointer arithmetic the original relies on (`&probs[-1]`, `&probs[copyCountBits]` with
//    copyCountBits == -1), which is undefined behavior even when the access that follows is fine.
//
//  - The original bounds-checks neither its input nor the back-reference copy. A PRX comes off a
//    memory stick, so a malformed one must fail rather than walk off the heap. Reads past the end
//    of the input are caught and end the stream; writes are checked against dstSize up front.

#include <algorithm>
#include <cstring>

#include "Common/CommonTypes.h"
#include "Common/Log.h"
#include "Core/Util/KL4E.h"

// The arithmetic decoder's state. `overrun` latches once the stream asks for a byte that isn't
// there - the reference just kept reading.
struct KLEDecoder {
	const u8 *in;
	const u8 *inEnd;
	u32 inputVal;
	u32 range;
	bool overrun;

	u8 NextByte() {
		if (in >= inEnd) {
			overrun = true;
			return 0;
		}
		return *in++;
	}
};

// One bit, against a probability that decays by `decay` and gains `bonus` when the bit comes up 1.
// Both stay within a byte by construction: 255 - (255 >> 3) + 31 == 255, and likewise for 4/15.
static int ReadBit(KLEDecoder *d, u8 *probPtr, u32 decay, u32 bonus) {
	u32 bound;
	u8 prob = *probPtr;
	if ((d->range >> 24) == 0) {
		d->inputVal = (d->inputVal << 8) + d->NextByte();
		bound = d->range * prob;
		d->range <<= 8;
	} else {
		bound = (d->range >> 8) * prob;
	}
	prob -= (prob >> decay);
	if (d->inputVal >= bound) {
		d->inputVal -= bound;
		d->range -= bound;
		*probPtr = prob;
		return 0;
	} else {
		d->range = bound;
		*probPtr = (u8)(prob + bonus);
		return 1;
	}
}

// The same, at a fixed probability of 1/2.
static int ReadBitUniform(KLEDecoder *d) {
	if ((d->range >> 24) == 0) {
		d->inputVal = (d->inputVal << 8) + d->NextByte();
		d->range <<= 7;
	} else {
		d->range >>= 1;
	}
	if (d->inputVal >= d->range) {
		d->inputVal -= d->range;
		return 0;
	}
	return 1;
}

// 1/2 again, without pulling a new byte in first.
static int ReadBitUniformNoNormal(KLEDecoder *d) {
	d->range >>= 1;
	if (d->inputVal >= d->range) {
		d->inputVal -= d->range;
		return 0;
	}
	return 1;
}

// Eight bits into one output byte. Which of the eight literal models is used depends on the output
// position and the previous byte, mixed by `shift` - see the note about addresses at the top.
static void OutputRaw(KLEDecoder *d, u8 *litProbs, u32 *curByte, u8 *out, size_t outOffset, u8 shift) {
	const u32 mask = (u32)((outOffset & 7) << 8) | (*curByte & 0xFF);
	// The reference forms `&litProbs[n * 255] - 1` and indexes it from 1, so keep the -1 in the
	// index instead of in a pointer that can sit before the array.
	const u32 probBase = ((mask >> shift) & 7) * 255;
	*curByte = 1;
	while (*curByte < 0x100) {
		u8 *curProb = &litProbs[probBase + *curByte - 1];
		*curByte <<= 1;
		if (ReadBit(d, curProb, 3, 31)) {
			*curByte |= 1;
		}
	}
	*out = *curByte & 0xff;
}

int DecompressKLE(u8 *dst, int dstSize, const u8 *src, int srcSize, bool isKl4e) {
	// Five bytes of header before any coded data: the parameter byte and the initial code word.
	if (!dst || !src || dstSize <= 0 || srcSize < 5) {
		return -1;
	}

	u8 litProbs[2040];
	u8 copyDistBitsProbs[304];
	u8 copyDistProbs[144];
	u8 copyCountBitsProbs[64];
	u8 copyCountProbs[256];

	u8 *const outBuf = dst;
	u8 *const outEnd = dst + dstSize;
	u8 *curOut = dst;
	u32 curByte = 0;
	u32 copyDist = 0, copyCount = 0;

	KLEDecoder d;
	d.in = src;
	d.inEnd = src + srcSize;
	d.range = 0xffffffff;
	d.overrun = false;
	d.inputVal = ((u32)src[1] << 24) | ((u32)src[2] << 16) | ((u32)src[3] << 8) | src[4];

	// Bit 7 of the parameter byte means the payload is stored, not compressed.
	if (src[0] & 0x80) {
		const u32 storedSize = d.inputVal;
		// The reference wants this strictly smaller than the output buffer, not equal.
		if (storedSize >= (u32)dstSize || storedSize > (u32)(srcSize - 5)) {
			return -1;
		}
		memcpy(dst, src + 5, storedSize);
		return (int)storedSize;
	}

	// Every model starts at the same value, chosen by two bits of the parameter byte.
	const u8 initial = (u8)(128 - (((src[0] >> 3) & 3) << 4));
	memset(litProbs, initial, sizeof(litProbs));
	memset(copyCountBitsProbs, initial, sizeof(copyCountBitsProbs));
	memset(copyDistBitsProbs, initial, sizeof(copyDistBitsProbs));
	memset(copyCountProbs, initial, sizeof(copyCountProbs));
	memset(copyDistProbs, initial, sizeof(copyDistProbs));

	// How much the literal model leans on output alignment versus the previous byte.
	const u8 shift = src[0] & 0x7;
	d.in = src + 5;

	// Indices rather than pointers, so the model selection below can't depend on the allocator and
	// nothing is ever formed outside its array. countBitsIdx in particular goes to -1 in the
	// reference, where only the read one past it is actually in bounds.
	s32 countBitsIdx = 0;
	s32 distBitsIdx = 0;

	OutputRaw(&d, litProbs, &curByte, curOut, (size_t)(curOut - outBuf), shift);

	while (true) {
		if (d.overrun) {
			return -1;
		}
		curOut++;

		// A 0 here means the next thing is another literal.
		if (ReadBit(&d, &copyCountBitsProbs[countBitsIdx], 4, 15) == 0) {
			countBitsIdx = std::max(countBitsIdx - 1, 0);
			if (curOut == outEnd) {
				return -1;
			}
			OutputRaw(&d, litProbs, &curByte, curOut, (size_t)(curOut - outBuf), shift);
			continue;
		}

		// Otherwise it's a back-reference. How many bits the length is written in comes first.
		copyCount = 1;
		s32 copyCountBits = -1;
		while (copyCountBits < 6) {
			countBitsIdx += 8;
			if (countBitsIdx + 1 > (s32)sizeof(copyCountBitsProbs)) {
				return -1;
			}
			if (!ReadBit(&d, &copyCountBitsProbs[countBitsIdx], 4, 15)) {
				break;
			}
			copyCountBits++;
		}

		s32 powLimit;
		if (copyCountBits >= 0) {
			const size_t outOffset = (size_t)(curOut - outBuf);
			const s32 probIdx = (copyCountBits << 5) |
				(s32)(((outOffset & 3) << (copyCountBits + 3)) & 0x18) |
				(countBitsIdx & 7);
			if (probIdx < 0 || probIdx + 24 >= (s32)sizeof(copyCountProbs)) {
				return -1;
			}
			u8 *probs = &copyCountProbs[probIdx];
			if (copyCountBits < 3) {
				copyCount = 1;
			} else {
				copyCount = 2 + ReadBit(&d, probs + 24, 3, 31);
				if (copyCountBits > 3) {
					copyCount = (copyCount << 1) | ReadBit(&d, probs + 24, 3, 31);
					if (copyCountBits > 4) {
						copyCount = (copyCount << 1) | ReadBitUniform(&d);
					}
					for (s32 i = 5; i < copyCountBits; i++) {
						copyCount = (copyCount << 1) | ReadBitUniformNoNormal(&d);
					}
				}
			}
			copyCount <<= 1;
			if (ReadBit(&d, probs, 3, 31)) {
				copyCount |= 1;
				if (copyCountBits <= 0) {
					powLimit = isKl4e ? 256 : 128;
					distBitsIdx = 56 + copyCountBits;
				}
			} else {
				if (copyCountBits <= 0) {
					powLimit = 64;
					distBitsIdx = copyCountBits;
				}
			}
			if (copyCountBits > 0) {
				copyCount = (copyCount << 1) | ReadBit(&d, probs + 8, 3, 31);
				if (copyCountBits != 1) {
					copyCount <<= 1;
					if (ReadBit(&d, probs + 16, 3, 31)) {
						copyCount += 1;
						if (copyCount == 0xFF) {
							// The end-of-stream marker.
							return (int)(curOut - outBuf);
						}
					}
				}
				distBitsIdx = 56 + copyCountBits;
				powLimit = isKl4e ? 256 : 128;
			}
		} else {
			powLimit = 64;
			distBitsIdx = copyCountBits;  // -1; only distBitsIdx + 1 is ever read.
		}

		// Then how many bits the distance is written in.
		s32 curPow = 8;
		bool skip = false;
		s32 copyDistBits;
		while (true) {
			if (d.overrun) {
				return -1;
			}
			const s32 probIdx = distBitsIdx + (curPow - 7);
			if (probIdx < 0 || probIdx >= (s32)sizeof(copyDistBitsProbs)) {
				return -1;
			}
			u8 *curProb = &copyDistBitsProbs[probIdx];
			curPow <<= 1;
			copyDistBits = curPow - powLimit;
			if (!ReadBit(&d, curProb, 3, 31)) {
				if (copyDistBits >= 0) {
					if (copyDistBits != 0) {
						copyDistBits -= 8;
						break;
					}
					copyDist = 0;
					// The reference compares a probability pointer against the output pointer here
					// and errors if they're equal. Those are separate objects, so it can't happen -
					// artart78 flagged it as a probable Sony bug. Dropped rather than ported as a
					// comparison the standard doesn't define.
					skip = true;  // Copy at distance zero.
					break;
				}
			} else {
				curPow += 8;
				if (copyDistBits >= 0) {
					break;
				}
			}
		}

		if (!skip) {
			if (copyDistBits < 0 || copyDistBits + 3 >= (s32)sizeof(copyDistProbs)) {
				return -1;
			}
			u8 *curProbs = &copyDistProbs[copyDistBits];
			s32 readBits = copyDistBits / 8;
			if (readBits < 3) {
				copyDist = 1;
			} else {
				copyDist = 2 + ReadBit(&d, curProbs + 3, 3, 31);
				if (readBits > 3) {
					copyDist = (copyDist << 1) | ReadBit(&d, curProbs + 3, 3, 31);
					if (readBits > 4) {
						copyDist = (copyDist << 1) | ReadBitUniform(&d);
						readBits--;
					}
					while (readBits > 4) {
						copyDist <<= 1;
						copyDist += ReadBitUniformNoNormal(&d);
						readBits--;
					}
				}
			}
			copyDist <<= 1;
			if (ReadBit(&d, curProbs, 3, 31)) {
				if (readBits > 0) {
					copyDist += 1;
				}
			} else {
				if (readBits <= 0) {
					copyDist -= 1;
				}
			}
			if (readBits > 0) {
				copyDist <<= 1;
				if (ReadBit(&d, curProbs + 1, 3, 31)) {
					if (readBits != 1) {
						copyDist += 1;
					}
				} else {
					if (readBits == 1) {
						copyDist -= 1;
					}
				}
				if (readBits != 1) {
					copyDist <<= 1;
					if (!ReadBit(&d, curProbs + 2, 3, 31)) {
						copyDist -= 1;
					}
				}
			}
			// Can't reach back before the start of the output.
			if (copyDist >= (u32)(curOut - outBuf)) {
				return -1;
			}
		}

		// Not in the reference, which trusts the length: copyCount + 1 bytes land at curOut.
		if ((u64)copyCount + 1 > (u64)(outEnd - curOut)) {
			return -1;
		}
		const u8 *from = curOut - copyDist - 1;
		for (u32 i = 0; i < copyCount + 1; i++) {
			curOut[i] = from[i];
		}
		curByte = curOut[copyCount];
		curOut += copyCount;
		countBitsIdx = 6 + (s32)((size_t)(curOut - outBuf) & 1);
	}
}
