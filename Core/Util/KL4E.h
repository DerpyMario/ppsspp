// SPDX-License-Identifier: GPL-3.0-or-later
//
// KL4E/KL3E decompression, ported from pspdecrypt's kl4e.c:
//   https://github.com/John-K/pspdecrypt  (GPL-3.0)
// reverse engineered from the PSP 6.60 firmware by artart78. The original is
// UtilsForKernel_6C6887EE in sysmem.prx.
//
// NOTE: unlike the rest of PPSSPP, which is GPL-2.0-or-later, this file is GPL-3.0-or-later,
// because the implementation it derives from is. Anything linking it is therefore GPL-3.0.

#pragma once

#include "Common/CommonTypes.h"

// Sony's compressor for firmware PRXes and PSAR entries: LZ77 over an arithmetic coder, close
// enough to LZMA in spirit. The two variants differ only in one constant, so they share a decoder.
//
// dst must have room for the whole decompressed result - there's no way to ask a stream how big it
// will be, so callers use the size the container records (a PRX header's elf_size, say).
// src points at the payload *including* its 5-byte header, but not the "KL4E"/"KL3E" magic.
//
// Returns the number of bytes written, or a negative value if the stream is malformed or would run
// past either end. Never reads past src + srcSize or writes past dst + dstSize, whatever the input.
int DecompressKLE(u8 *dst, int dstSize, const u8 *src, int srcSize, bool isKl4e);
