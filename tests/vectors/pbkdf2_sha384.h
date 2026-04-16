/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * pbkdf2_sha384.h — PBKDF2-HMAC-SHA384 known-answer test vectors
 *
 * Test vectors computed independently and cross-validated:
 *   - Python 3: hashlib.pbkdf2_hmac('sha384', password, salt, iterations, dklen)
 *   - OpenSSL 3: openssl kdf -keylen N -kdfopt digest:SHA384
 *                  -kdfopt "pass:..." -kdfopt "salt:..." -kdfopt iter:N PBKDF2
 *
 * Salt lengths are >= 16 bytes (128 bits) as required by SP 800-132 §5.1.
 * Iteration counts are >= 1000 as required by SP 800-132 §5.2.
 *
 * Do NOT modify these values. Do NOT generate vectors from the code under test.
 */

#ifndef CRYPTO2DEV_VECTORS_PBKDF2_SHA384_H
#define CRYPTO2DEV_VECTORS_PBKDF2_SHA384_H

struct pbkdf2_sha384_vector {
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
 * dkLen      = 48
 * DK         = 563d193c3816e6e136358290e1f9dfb2
 *              8d4e79aab7fc079e6ca6a1a8696e53c9
 *              76ffefdeb842269edcdec104c4e1a376
 *
 * Verified: Python hashlib + OpenSSL 3 agree.
 */
static const unsigned char pbkdf2_sha384_tc1_password[] = "password";
static const unsigned char pbkdf2_sha384_tc1_salt[]     = "saltsaltsaltsalt";
static const unsigned char pbkdf2_sha384_tc1_dk[] = {
	0x56, 0x3d, 0x19, 0x3c, 0x38, 0x16, 0xe6, 0xe1,
	0x36, 0x35, 0x82, 0x90, 0xe1, 0xf9, 0xdf, 0xb2,
	0x8d, 0x4e, 0x79, 0xaa, 0xb7, 0xfc, 0x07, 0x9e,
	0x6c, 0xa6, 0xa1, 0xa8, 0x69, 0x6e, 0x53, 0xc9,
	0x76, 0xff, 0xef, 0xde, 0xb8, 0x42, 0x26, 0x9e,
	0xdc, 0xde, 0xc1, 0x04, 0xc4, 0xe1, 0xa3, 0x76,
};

/* ── TC2: longer inputs, higher iteration count ───────────────────────────── */
/*
 * password   = "passwordPASSWORDpassword" (24 bytes)
 * salt       = "saltSALTsaltSALTsaltSALT" (24 bytes)
 * iterations = 4096
 * dkLen      = 48
 * DK         = 34ea637498c627cd2d9d3ea4be1de93a
 *              5cf95c24ee635f09e7aba4bd648029a8
 *              0f498c365ed079a2b76a4e0c89f54540
 *
 * Verified: Python hashlib + OpenSSL 3 agree.
 */
static const unsigned char pbkdf2_sha384_tc2_password[] = "passwordPASSWORDpassword";
static const unsigned char pbkdf2_sha384_tc2_salt[]     = "saltSALTsaltSALTsaltSALT";
static const unsigned char pbkdf2_sha384_tc2_dk[] = {
	0x34, 0xea, 0x63, 0x74, 0x98, 0xc6, 0x27, 0xcd,
	0x2d, 0x9d, 0x3e, 0xa4, 0xbe, 0x1d, 0xe9, 0x3a,
	0x5c, 0xf9, 0x5c, 0x24, 0xee, 0x63, 0x5f, 0x09,
	0xe7, 0xab, 0xa4, 0xbd, 0x64, 0x80, 0x29, 0xa8,
	0x0f, 0x49, 0x8c, 0x36, 0x5e, 0xd0, 0x79, 0xa2,
	0xb7, 0x6a, 0x4e, 0x0c, 0x89, 0xf5, 0x45, 0x40,
};

/* ── TC3: different password and salt ────────────────────────────────────── */
/*
 * password   = "hunter42" (8 bytes)
 * salt       = "deadbeefdeadbeef" (16 bytes)
 * iterations = 2000
 * dkLen      = 48
 * DK         = 150ea657873876c03ec2a15e8678c064
 *              24dddaf98224fc7df6aef8a3d2f98a69
 *              10ab92ed417049afe49f3909d5e9bf69
 *
 * Verified: Python hashlib + OpenSSL 3 agree.
 */
static const unsigned char pbkdf2_sha384_tc3_password[] = "hunter42";
static const unsigned char pbkdf2_sha384_tc3_salt[]     = "deadbeefdeadbeef";
static const unsigned char pbkdf2_sha384_tc3_dk[] = {
	0x15, 0x0e, 0xa6, 0x57, 0x87, 0x38, 0x76, 0xc0,
	0x3e, 0xc2, 0xa1, 0x5e, 0x86, 0x78, 0xc0, 0x64,
	0x24, 0xdd, 0xda, 0xf9, 0x82, 0x24, 0xfc, 0x7d,
	0xf6, 0xae, 0xf8, 0xa3, 0xd2, 0xf9, 0x8a, 0x69,
	0x10, 0xab, 0x92, 0xed, 0x41, 0x70, 0x49, 0xaf,
	0xe4, 0x9f, 0x39, 0x09, 0xd5, 0xe9, 0xbf, 0x69,
};

/* ── Vector table ───────────────────────────────────────────────────────── */

static const struct pbkdf2_sha384_vector pbkdf2_sha384_vectors[] = {
	{
		.password     = pbkdf2_sha384_tc1_password,
		.password_len = 8,   /* "password", no NUL */
		.salt         = pbkdf2_sha384_tc1_salt,
		.salt_len     = 16,  /* "saltsaltsaltsalt", no NUL */
		.iterations   = 1000,
		.dk_len       = sizeof(pbkdf2_sha384_tc1_dk),
		.dk           = pbkdf2_sha384_tc1_dk,
		.source       = "PBKDF2-HMAC-SHA384: pw=password salt=saltsaltsaltsalt iter=1000",
	},
	{
		.password     = pbkdf2_sha384_tc2_password,
		.password_len = 24,  /* "passwordPASSWORDpassword", no NUL */
		.salt         = pbkdf2_sha384_tc2_salt,
		.salt_len     = 24,  /* "saltSALTsaltSALTsaltSALT", no NUL */
		.iterations   = 4096,
		.dk_len       = sizeof(pbkdf2_sha384_tc2_dk),
		.dk           = pbkdf2_sha384_tc2_dk,
		.source       = "PBKDF2-HMAC-SHA384: pw=passwordPASSWORDpassword iter=4096",
	},
	{
		.password     = pbkdf2_sha384_tc3_password,
		.password_len = 8,   /* "hunter42", no NUL */
		.salt         = pbkdf2_sha384_tc3_salt,
		.salt_len     = 16,  /* "deadbeefdeadbeef", no NUL */
		.iterations   = 2000,
		.dk_len       = sizeof(pbkdf2_sha384_tc3_dk),
		.dk           = pbkdf2_sha384_tc3_dk,
		.source       = "PBKDF2-HMAC-SHA384: pw=hunter42 salt=deadbeefdeadbeef iter=2000",
	},
};

#define PBKDF2_SHA384_VECTOR_COUNT \
	(sizeof(pbkdf2_sha384_vectors) / sizeof(pbkdf2_sha384_vectors[0]))

#endif /* CRYPTO2DEV_VECTORS_PBKDF2_SHA384_H */
