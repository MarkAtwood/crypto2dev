/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * sha256.h — SHA-256 and SHA-224 known-answer test vectors
 *
 * Source: NIST FIPS 180-4, §B.1 example computations
 *   https://csrc.nist.gov/publications/detail/fips/180/4/final
 *
 * Verified against gogood-wolfssl wolfcrypt/sha256/sha256_test.go.
 * Do NOT modify these values. Do NOT generate vectors from the code under test.
 */
#ifndef CRYPTO2DEV_VECTORS_SHA256_H
#define CRYPTO2DEV_VECTORS_SHA256_H

struct sha256_vector {
	const unsigned char *input;
	unsigned int         input_len;
	const unsigned char  digest[32];   /* SHA-256 output (32 bytes) */
	const char          *source;
};

/* ── SHA-256 vectors — NIST FIPS 180-4 ─────────────────────────────────── */

static const struct sha256_vector sha256_vectors[] = {
	{
		/* FIPS 180-4 §B.1: SHA-256("") */
		.input     = (const unsigned char *)"",
		.input_len = 0,
		.digest    = {
			0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
			0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
			0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
			0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
		},
		.source = "NIST FIPS 180-4 §B.1: SHA-256(empty)",
	},
	{
		/* FIPS 180-4 §B.1: SHA-256("abc") */
		.input     = (const unsigned char *)"abc",
		.input_len = 3,
		.digest    = {
			0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
			0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
			0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
			0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
		},
		.source = "NIST FIPS 180-4 §B.1: SHA-256(\"abc\")",
	},
	{
		/* FIPS 180-4 §B.2: SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") */
		.input     = (const unsigned char *)
			     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmn"
			     "lmnomnopnopq",
		.input_len = 56,
		.digest    = {
			0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
			0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
			0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
			0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
		},
		.source = "NIST FIPS 180-4 §B.2: SHA-256(448-bit message)",
	},
	{
		/* SHA-256 of 64 × 'a' — verified against gogood-wolfssl sha256_test.go */
		.input     = (const unsigned char *)
			     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		.input_len = 64,
		.digest    = {
			0xff, 0xe0, 0x54, 0xfe, 0x7a, 0xe0, 0xcb, 0x6d,
			0xc6, 0x5c, 0x3a, 0xf9, 0xb6, 0x1d, 0x52, 0x09,
			0xf4, 0x39, 0x85, 0x1d, 0xb4, 0x3d, 0x0b, 0xa5,
			0x99, 0x73, 0x37, 0xdf, 0x15, 0x46, 0x68, 0xeb,
		},
		.source = "gogood-wolfssl sha256_test.go: SHA-256(64 x 'a')",
	},
};

#define SHA256_VECTOR_COUNT \
	((int)(sizeof(sha256_vectors) / sizeof(sha256_vectors[0])))

#endif /* CRYPTO2DEV_VECTORS_SHA256_H */
