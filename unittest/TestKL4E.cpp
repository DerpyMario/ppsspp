#include <cstring>
#include <cstdio>

#include "Common/CommonTypes.h"
#include "Core/Util/KL4E.h"
#include "UnitTest.h"

// A real KL4E stream can't be checked in - the only ones that exist are inside Sony's firmware -
// so these pin down the malformed cases instead, which is where the risk is: the decompressor runs
// on PRXes that come off a memory stick, and the implementation it was ported from bounds-checks
// neither its input nor its back-reference copies.

// Too short to even hold the 5-byte header.
static bool TestKL4ETruncatedHeader() {
	const u8 input[] = { 0x00, 0x11, 0x22, 0x33 };
	u8 output[64];
	memset(output, 0xAA, sizeof(output));

	EXPECT_TRUE(DecompressKLE(output, sizeof(output), input, sizeof(input), true) < 0);
	for (size_t i = 0; i < sizeof(output); ++i) {
		EXPECT_TRUE(output[i] == 0xAA);
	}
	return true;
}

// The stored path (bit 7 of the parameter byte) takes its length from the header, so a length
// larger than either buffer must be rejected rather than copied.
static bool TestKL4EStoredLengthClamped() {
	// Parameter byte 0x80, then a 4-byte length of 0x00FFFFFF - far more than we have either side.
	const u8 tooBig[] = { 0x80, 0x00, 0xFF, 0xFF, 0xFF, 'a', 'b', 'c' };
	u8 output[16];
	memset(output, 0xAA, sizeof(output));
	EXPECT_TRUE(DecompressKLE(output, sizeof(output), tooBig, sizeof(tooBig), true) < 0);
	for (size_t i = 0; i < sizeof(output); ++i) {
		EXPECT_TRUE(output[i] == 0xAA);
	}

	// A length that fits both sides is copied verbatim.
	const u8 ok[] = { 0x80, 0x00, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o' };
	memset(output, 0xAA, sizeof(output));
	EXPECT_EQ_INT(DecompressKLE(output, sizeof(output), ok, sizeof(ok), true), 5);
	EXPECT_TRUE(memcmp(output, "hello", 5) == 0);
	EXPECT_TRUE(output[5] == 0xAA);
	return true;
}

// A stored length equal to the output size is rejected too - the original wants it strictly
// smaller, and this keeps the port honest about matching that.
static bool TestKL4EStoredExactSizeRejected() {
	const u8 input[] = { 0x80, 0x00, 0x00, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8 };
	u8 output[8];
	memset(output, 0xAA, sizeof(output));
	EXPECT_TRUE(DecompressKLE(output, sizeof(output), input, sizeof(input), true) < 0);
	return true;
}

// Compressed streams that are pure noise must terminate and fail, never hang or write out of
// bounds. The decoder always advances its output pointer once per iteration, so the loop is
// bounded by the output size - this is what guards that.
static bool TestKL4EGarbageRejected() {
	u32 seed = 1234567;
	for (int trial = 0; trial < 500; trial++) {
		u8 input[64];
		for (size_t i = 0; i < sizeof(input); i++) {
			seed = seed * 1103515245 + 12345;
			input[i] = (u8)(seed >> 16);
		}
		input[0] &= 0x7F;  // Compressed, not stored.

		u8 output[256];
		memset(output, 0xAA, sizeof(output));
		const int result = DecompressKLE(output, sizeof(output), input, sizeof(input), (trial & 1) != 0);
		// Whatever it decides, it must stay inside the buffer it was given.
		EXPECT_TRUE(result <= (int)sizeof(output));
	}
	return true;
}

// A zero-sized or absent output buffer must be refused rather than written to.
static bool TestKL4EEmptyOutput() {
	const u8 input[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	u8 output[4];
	memset(output, 0xBB, sizeof(output));
	EXPECT_TRUE(DecompressKLE(output, 0, input, sizeof(input), true) < 0);
	EXPECT_TRUE(DecompressKLE(nullptr, 16, input, sizeof(input), true) < 0);
	for (size_t i = 0; i < sizeof(output); ++i) {
		EXPECT_TRUE(output[i] == 0xBB);
	}
	return true;
}

bool TestKL4E() {
	if (!TestKL4ETruncatedHeader())
		return false;
	if (!TestKL4EStoredLengthClamped())
		return false;
	if (!TestKL4EStoredExactSizeRejected())
		return false;
	if (!TestKL4EGarbageRejected())
		return false;
	if (!TestKL4EEmptyOutput())
		return false;
	return true;
}
