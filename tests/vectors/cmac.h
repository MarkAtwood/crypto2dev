/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * cmac.h — AES-128-CMAC known-answer test vectors
 *
 * Source: NIST SP 800-38B, §D.1 (AES-128 examples)
 *   https://csrc.nist.gov/publications/detail/sp/800-38b/final
 *
 * Verified against gogood-wolfssl wolfcrypt/cmac/cmac_test.go and
 * golang-wolfssl wolfssl-src/wolfcrypt/test/test.c cmac_test().
 * Do NOT modify these values. Do NOT generate vectors from the code under test.
 */
#ifndef CRYPTO2DEV_VECTORS_CMAC_H
#define CRYPTO2DEV_VECTORS_CMAC_H

struct cmac_vector {
	const unsigned char *key;
	unsigned int         key_len;
	const unsigned char *msg;
	unsigned int         msg_len;
	const unsigned char  tag[16];   /* AES-CMAC output (16 bytes) */
	const char          *source;
};

/* ── NIST SP 800-38B §D.1 — AES-128 key and message ────────────────────── */

/* NIST Example 1–4 key (same key for all four vectors) */
static const unsigned char cmac_key_128[] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

/*
 * NIST 64-byte message block.
 * Vectors use the first 0, 16, 40, or 64 bytes of this block.
 */
static const unsigned char cmac_msg_64[] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
	0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
	0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
	0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
	0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
};

/* ── AES-128-CMAC vector table ──────────────────────────────────────────── */

static const struct cmac_vector cmac_vectors[] = {
	{
		/* NIST SP 800-38B §D.1 Example 1: empty message */
		.key     = cmac_key_128,
		.key_len = 16,
		.msg     = cmac_msg_64,
		.msg_len = 0,
		.tag     = {
			0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
			0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46,
		},
		.source  = "NIST SP 800-38B §D.1 Example 1: AES-128-CMAC(empty)",
	},
	{
		/* NIST SP 800-38B §D.1 Example 2: 16-byte message */
		.key     = cmac_key_128,
		.key_len = 16,
		.msg     = cmac_msg_64,
		.msg_len = 16,
		.tag     = {
			0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
			0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c,
		},
		.source  = "NIST SP 800-38B §D.1 Example 2: AES-128-CMAC(16 bytes)",
	},
	{
		/* NIST SP 800-38B §D.1 Example 3: 40-byte message */
		.key     = cmac_key_128,
		.key_len = 16,
		.msg     = cmac_msg_64,
		.msg_len = 40,
		.tag     = {
			0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
			0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27,
		},
		.source  = "NIST SP 800-38B §D.1 Example 3: AES-128-CMAC(40 bytes)",
	},
	{
		/* NIST SP 800-38B §D.1 Example 4: 64-byte message */
		.key     = cmac_key_128,
		.key_len = 16,
		.msg     = cmac_msg_64,
		.msg_len = 64,
		.tag     = {
			0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
			0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe,
		},
		.source  = "NIST SP 800-38B §D.1 Example 4: AES-128-CMAC(64 bytes)",
	},
};

#define CMAC_VECTOR_COUNT \
	((int)(sizeof(cmac_vectors) / sizeof(cmac_vectors[0])))

#endif /* CRYPTO2DEV_VECTORS_CMAC_H */
