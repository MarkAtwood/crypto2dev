/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * hkdf.h — HKDF-SHA256 known-answer test vectors
 *
 * Source: RFC 5869 Appendix A, Test Cases 1 and 3
 *   https://www.rfc-editor.org/rfc/rfc5869
 *
 * Only SHA-256 is included; Test Case 2 (L=82) is excluded because it
 * exceeds CRYPTO2DEV_KDF_OKM_MAXLEN (64 bytes).
 *
 * Verified independently against:
 *   - Python 3 hashlib (HMAC-based manual extract/expand)
 *   - OpenSSL 3: openssl kdf -keylen N -kdfopt digest:SHA256
 *                  -kdfopt hexkey:... -kdfopt hexsalt:... -kdfopt hexinfo:...
 *                  HKDF
 *
 * Do NOT modify these values. Do NOT generate vectors from the code under test.
 */

#ifndef CRYPTO2DEV_VECTORS_HKDF_H
#define CRYPTO2DEV_VECTORS_HKDF_H

#include <stddef.h>  /* NULL */

struct hkdf_vector {
	const unsigned char *ikm;
	unsigned int         ikm_len;
	const unsigned char *salt;     /* NULL or pointer to salt bytes */
	unsigned int         salt_len;
	const unsigned char *info;     /* NULL or pointer to info bytes */
	unsigned int         info_len;
	unsigned int         okm_len;
	const unsigned char *okm;
	const char          *source;
};

/* ── RFC 5869 Test Case 1 ───────────────────────────────────────────────── */
/*
 * Hash  = SHA-256
 * IKM   = 0x0b0b...0b (22 bytes)
 * salt  = 0x000102030405060708090a0b0c (13 bytes)
 * info  = 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
 * L     = 42 bytes
 * OKM   = 3cb25f25faacd57a90434f64d0362f2a
 *         2d2d0a90cf1a5a4c5db02d56ecc4c5bf
 *         34007208d5b887185865
 */
static const unsigned char hkdf_sha256_tc1_ikm[] = {
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};
static const unsigned char hkdf_sha256_tc1_salt[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c
};
static const unsigned char hkdf_sha256_tc1_info[] = {
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
	0xf8, 0xf9
};
static const unsigned char hkdf_sha256_tc1_okm[] = {
	0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
	0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
	0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
	0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
	0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
	0x58, 0x65
};

/* ── RFC 5869 Test Case 3 ───────────────────────────────────────────────── */
/*
 * Hash  = SHA-256
 * IKM   = 0x0b0b...0b (22 bytes)
 * salt  = not provided (salt_len = 0; RFC 5869 §2.2 uses zero-filled salt)
 * info  = not provided (info_len = 0)
 * L     = 42 bytes
 * OKM   = 8da4e775a563c18f715f802a063c5a31
 *         b8a11f5c5ee1879ec3454e5f3c738d2d
 *         9d201395faa4b61a96c8
 */
static const unsigned char hkdf_sha256_tc3_ikm[] = {
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};
static const unsigned char hkdf_sha256_tc3_okm[] = {
	0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f,
	0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
	0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e,
	0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
	0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a,
	0x96, 0xc8
};

/* ── Vector table ───────────────────────────────────────────────────────── */

static const struct hkdf_vector hkdf_sha256_vectors[] = {
	{
		.ikm      = hkdf_sha256_tc1_ikm,
		.ikm_len  = sizeof(hkdf_sha256_tc1_ikm),
		.salt     = hkdf_sha256_tc1_salt,
		.salt_len = sizeof(hkdf_sha256_tc1_salt),
		.info     = hkdf_sha256_tc1_info,
		.info_len = sizeof(hkdf_sha256_tc1_info),
		.okm_len  = sizeof(hkdf_sha256_tc1_okm),
		.okm      = hkdf_sha256_tc1_okm,
		.source   = "RFC 5869 Appendix A Test Case 1 (SHA-256, with salt and info)",
	},
	{
		.ikm      = hkdf_sha256_tc3_ikm,
		.ikm_len  = sizeof(hkdf_sha256_tc3_ikm),
		.salt     = NULL,
		.salt_len = 0,
		.info     = NULL,
		.info_len = 0,
		.okm_len  = sizeof(hkdf_sha256_tc3_okm),
		.okm      = hkdf_sha256_tc3_okm,
		.source   = "RFC 5869 Appendix A Test Case 3 (SHA-256, no salt, no info)",
	},
};

#define HKDF_SHA256_VECTOR_COUNT \
	(sizeof(hkdf_sha256_vectors) / sizeof(hkdf_sha256_vectors[0]))

#endif /* CRYPTO2DEV_VECTORS_HKDF_H */
