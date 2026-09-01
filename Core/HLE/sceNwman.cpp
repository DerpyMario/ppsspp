// Copyright (c) 2026- PPSSPP Project.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 2.0 or later versions.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License 2.0 for more details.

// A copy of the GPL 2.0 should have been included with the program.
// If not, see http://www.gnu.org/licenses/

// Official git repository and contact information can be found at
// https://github.com/hrydgard/ppsspp and http://www.ppsspp.org/.

// The one function of sceNwman that anything asks for: the block decrypt behind a firmware
// updater's PSAR reader.
//
// A 1.00 updater runs its own scePSAR_Driver.prx to walk DATA.BIN, and that driver does no crypto
// itself - it imports sceNwman_driver/9555D68D and calls it on each encrypted record. Nothing
// supplies that module: it isn't in the updater, and 1.00's flash0 has no nwman.prx, so the import
// went unresolved and the driver trapped the moment the updater got as far as reading its archive.
//
// The call sites in scePSAR_Driver settle both the shape and the meaning. scePSAR_3f7c1edc reads a
// 0x260-byte entry header and, when the context byte at +0x0C says the archive is encrypted, does
//
//     move  $a0, $s1            ; the record
//     addiu $a1, $zero, 0x260   ; its size
//     jal   <nwman stub>
//     move  $a2, $sp            ; a scratch word
//     bgez  $v0, ...            ; >= 0 means it worked
//
// then copies the record - the same buffer it passed in - to the caller. So the decrypt is in
// place, and a negative return is the only failure signal. scePSAR_e564b1da does the same with the
// size from its context at +0x104. Neither reads the word behind $a2 afterwards.
//
// That is exactly what PSARReader::DecodeBlock does offline, so this shares its decrypter rather
// than growing a second one - see Core/Util/PSARUnpack.cpp and Core/ELF/PrxDecrypter.cpp. The
// version-1 archives this driver reads are the ones that skip the AES "demangle" step, so the
// record goes straight to pspDecryptPRX, keyed by the tag at +0xD0.

#include <vector>

#include "Common/CommonTypes.h"
#include "Common/Log.h"
#include "Common/Swap.h"

#include "Core/ELF/PrxDecrypter.h"
#include "Core/HLE/ErrorCodes.h"
#include "Core/HLE/HLE.h"
#include "Core/HLE/FunctionWrappers.h"
#include "Core/HLE/sceNwman.h"
#include "Core/MemMap.h"
#include "Core/MemMapHelpers.h"

// The decrypter reads a little past the record it's given and uses what it finds, so hand it the
// bytes that really follow whenever the guest has them - matching what DecodeBlock does with the
// archive in memory. Only the record itself is written back.
static const u32 NWMAN_SLACK = 0x10;

// Same bound PSARUnpack puts on a single record, so a bogus size can't ask for a huge allocation.
static const u32 NWMAN_MAX_BLOCK = 64 * 1024 * 1024;

static int sceNwman_9555D68D(u32 bufAddr, u32 size, u32 outSizeAddr) {
	if (size == 0 || size > NWMAN_MAX_BLOCK) {
		return hleLogError(Log::HLE, SCE_KERNEL_ERROR_ILLEGAL_SIZE, "bad size");
	}
	if (!Memory::IsValidRange(bufAddr, size)) {
		return hleLogError(Log::HLE, SCE_KERNEL_ERROR_ILLEGAL_ADDR, "bad buffer");
	}

	// Take a copy so a decrypt that fails part way through can't leave the guest's record mangled -
	// the driver retries the same bytes with a different record size when a block doesn't fit.
	std::vector<u8> block(size + NWMAN_SLACK, 0);
	const u32 slack = Memory::ClampValidSizeAt(bufAddr + size, NWMAN_SLACK);
	Memory::Memcpy(block.data(), bufAddr, size + slack, "NwmanDecrypt");

	const int decrypted = pspDecryptPRX(block.data(), block.data(), size);
	if (decrypted <= 0) {
		// Not fatal for the updater - it tries other record sizes before giving up - so this is a
		// warning rather than an error, and the tag is the useful part when one really is unknown.
		return hleLogWarning(Log::HLE, SCE_KERNEL_ERROR_ERROR, "couldn't decrypt %d bytes (tag %08x)",
			size, block.size() >= 0xD4 ? *(u32_le *)&block[0xD0] : 0);
	}
	if ((u32)decrypted > size) {
		return hleLogError(Log::HLE, SCE_KERNEL_ERROR_ERROR, "decrypt overran: %d > %d", decrypted, size);
	}

	// The whole record goes back, not just the plaintext prefix: the decrypt is in place on real
	// hardware, and scePSAR_3f7c1edc copies all 0x260 bytes on regardless of the 0x110 it will
	// actually read. Leaving the tail as the original ciphertext would be a difference for no gain.
	Memory::Memcpy(bufAddr, block.data(), size, "NwmanDecrypt");
	// Written for completeness; the driver passes a stack slot here and never looks at it.
	if (Memory::IsValidRange(outSizeAddr, 4)) {
		Memory::WriteUnchecked_U32((u32)decrypted, outSizeAddr);
	}
	return hleLogDebug(Log::HLE, decrypted);
}

const HLEFunction sceNwman_driver[] = {
	{0X9555D68D, &WrapI_UUU<sceNwman_9555D68D>, "sceNwman_9555D68D", 'i', "xxx", HLE_KERNEL_SYSCALL },
};

void Register_sceNwman_driver() {
	RegisterHLEModule("sceNwman_driver", ARRAY_SIZE(sceNwman_driver), sceNwman_driver);
}
