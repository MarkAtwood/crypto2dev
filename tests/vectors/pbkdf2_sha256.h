/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * pbkdf2_sha256.h — PBKDF2-HMAC-SHA256 known-answer test vectors
 *
 * Test vectors computed independently and cross-validated:
 *   - Python 3: hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen)
 *   - OpenSSL 3: openssl kdf -keylen N -kdfopt digest:SHA256
 *                  -kdfopt "pass:..." -kdfopt "salt:..." -kdfopt iter:N PBKDF2
 *
 * Salt lengths are >= 16 bytes (128 bits) as required by SP 800-132 §5.1.
 * Iteration counts are >= 1000 as required by SP 800-132 §5.2.
 *
 * Note: RFC 6070 vectors use SHA-1 (not SHA-256) and are not used here.
 *
 * Do NOT modify these values. Do NOT generate vectors from the code under test.
 */

#ifndef CRYPTO2DEV_VECTORS_PBKDF2_SHA256_H
#define CRYPTO2DEV_VECTORS_PBKDF2_SHA256_H

struct pbkdf2_sha256_vector {
	const unsigned char *password;
	unsigned int         password_len;
	const unsigned char *salt;
	unsigned int         salt_len;
	unsigned int         iterations;
	unsigned int         dk_len;
	const unsigned char *dk;
	const char          *source;
};

/* ── TC1: minimal parameters ─────────────────────────────────────────────── */
/*
 * password   = "password" (8 bytes)
 * salt       = "saltsaltsaltsalt" (16 bytes)
 * iterations = 1000
 * dkLen      = 32
 * DK         = f275fb870144cc807c68f6a325360af3
 *              078741ce4d833d2915500abd2bb88d00
 *
 * Verified: Python hashlib + OpenSSL 3 agree.
 */
static const unsigned char pbkdf2_sha256_tc1_password[] = "password";
static const unsigned char pbkdf2_sha256_tc1_salt[]     = "saltsaltsaltsalt";
static const unsigned char pbkdf2_sha256_tc1_dk[] = {
	0xf2, 0x75, 0xfb, 0x87, 0x01, 0x44, 0xcc, 0x80,
	0x7c, 0x68, 0xf6, 0xa3, 0x25, 0x36, 0x0a, 0xf3,
	0x07, 0x87, 0x41, 0xce, 0x4d, 0x83, 0x3d, 0x29,
	0x15, 0x50, 0x0a, 0xbd, 0x2b, 0xb8, 0x8d, 0x00,
};

/* ── TC2: longer inputs, higher iteration count ───────────────────────────── */
/*
 * password   = "passwordPASSWORDpassword" (24 bytes)
 * salt       = "saltSALTsaltSALTsaltSALT" (24 bytes)
 * iterations = 4096
 * dkLen      = 32
 * DK         = 619357d665af3c74f1112a49aa13cde5
 *              421e1a0d08bd40bbdc73cfa94412e469
 *
 * Verified: Python hashlib + OpenSSL 3 agree.
 */
static const unsigned char pbkdf2_sha256_tc2_password[] = "passwordPASSWORDpassword";
static const unsigned char pbkdf2_sha256_tc2_salt[]     = "saltSALTsaltSALTsaltSALT";
static const unsigned char pbkdf2_sha256_tc2_dk[] = {
	0x61, 0x93, 0x57, 0xd6, 0x65, 0xaf, 0x3c, 0x74,
	0xf1, 0x11, 0x2a, 0x49, 0xaa, 0x13, 0xcd, 0xe5,
	0x42, 0x1e, 0x1a, 0x0d, 0x08, 0xbd, 0x40, 0xbb,
	0xdc, 0x73, 0xcf, 0xa9, 0x44, 0x12, 0xe4, 0x69,
};

/* ── Vector table ───────────────────────────────────────────────────────── */

static const struct pbkdf2_sha256_vector pbkdf2_sha256_vectors[] = {
	{
		.password     = pbkdf2_sha256_tc1_password,
		.password_len = 8,   /* "password", no NUL */
		.salt         = pbkdf2_sha256_tc1_salt,
		.salt_len     = 16,  /* "saltsaltsaltsalt", no NUL */
		.iterations   = 1000,
		.dk_len       = sizeof(pbkdf2_sha256_tc1_dk),
		.dk           = pbkdf2_sha256_tc1_dk,
		.source       = "PBKDF2-HMAC-SHA256: pw=password salt=saltsaltsaltsalt iter=1000",
	},
	{
		.password     = pbkdf2_sha256_tc2_password,
		.password_len = 24,  /* "passwordPASSWORDpassword", no NUL */
		.salt         = pbkdf2_sha256_tc2_salt,
		.salt_len     = 24,  /* "saltSALTsaltSALTsaltSALT", no NUL */
		.iterations   = 4096,
		.dk_len       = sizeof(pbkdf2_sha256_tc2_dk),
		.dk           = pbkdf2_sha256_tc2_dk,
		.source       = "PBKDF2-HMAC-SHA256: pw=passwordPASSWORDpassword iter=4096",
	},
};

#define PBKDF2_SHA256_VECTOR_COUNT \
	(sizeof(pbkdf2_sha256_vectors) / sizeof(pbkdf2_sha256_vectors[0]))

#endif /* CRYPTO2DEV_VECTORS_PBKDF2_SHA256_H */
