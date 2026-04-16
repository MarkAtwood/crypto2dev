/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * pbkdf2_sha512.h — PBKDF2-HMAC-SHA512 known-answer test vectors
 *
 * Test vectors computed independently and cross-validated:
 *   - Python 3: hashlib.pbkdf2_hmac('sha512', password, salt, iterations, dklen)
 *   - OpenSSL 3: openssl kdf -keylen N -kdfopt digest:SHA512
 *                  -kdfopt "pass:..." -kdfopt "salt:..." -kdfopt iter:N PBKDF2
 *
 * Salt lengths are >= 16 bytes (128 bits) as required by SP 800-132 §5.1.
 * Iteration counts are >= 1000 as required by SP 800-132 §5.2.
 *
 * Do NOT modify these values. Do NOT generate vectors from the code under test.
 */

#ifndef CRYPTO2DEV_VECTORS_PBKDF2_SHA512_H
#define CRYPTO2DEV_VECTORS_PBKDF2_SHA512_H

struct pbkdf2_sha512_vector {
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
 * dkLen      = 64
 * DK         = ef5e6ba88af97573953e9061aaab2e82
 *              5d37ef34f96d6253598999b4870af210
 *              678ac2a9c1f63b92892fc230eb347a87
 *              845e743dbecc0fa1ef909c220d0c38c3
 *
 * Verified: Python hashlib + OpenSSL 3 agree.
 */
static const unsigned char pbkdf2_sha512_tc1_password[] = "password";
static const unsigned char pbkdf2_sha512_tc1_salt[]     = "saltsaltsaltsalt";
static const unsigned char pbkdf2_sha512_tc1_dk[] = {
	0xef, 0x5e, 0x6b, 0xa8, 0x8a, 0xf9, 0x75, 0x73,
	0x95, 0x3e, 0x90, 0x61, 0xaa, 0xab, 0x2e, 0x82,
	0x5d, 0x37, 0xef, 0x34, 0xf9, 0x6d, 0x62, 0x53,
	0x59, 0x89, 0x99, 0xb4, 0x87, 0x0a, 0xf2, 0x10,
	0x67, 0x8a, 0xc2, 0xa9, 0xc1, 0xf6, 0x3b, 0x92,
	0x89, 0x2f, 0xc2, 0x30, 0xeb, 0x34, 0x7a, 0x87,
	0x84, 0x5e, 0x74, 0x3d, 0xbe, 0xcc, 0x0f, 0xa1,
	0xef, 0x90, 0x9c, 0x22, 0x0d, 0x0c, 0x38, 0xc3,
};

/* ── TC2: longer inputs, higher iteration count ───────────────────────────── */
/*
 * password   = "passwordPASSWORDpassword" (24 bytes)
 * salt       = "saltSALTsaltSALTsaltSALT" (24 bytes)
 * iterations = 4096
 * dkLen      = 64
 * DK         = 75f34e90c4b738df532472a4909e4431
 *              1364ee55fa95c44cb0ea9b263e2e3549
 *              23b596a18ced5228b37aa9c9c32a8996
 *              b4b7223c72877f9f5981e39a27f28c05
 *
 * Verified: Python hashlib + OpenSSL 3 agree.
 */
static const unsigned char pbkdf2_sha512_tc2_password[] = "passwordPASSWORDpassword";
static const unsigned char pbkdf2_sha512_tc2_salt[]     = "saltSALTsaltSALTsaltSALT";
static const unsigned char pbkdf2_sha512_tc2_dk[] = {
	0x75, 0xf3, 0x4e, 0x90, 0xc4, 0xb7, 0x38, 0xdf,
	0x53, 0x24, 0x72, 0xa4, 0x90, 0x9e, 0x44, 0x31,
	0x13, 0x64, 0xee, 0x55, 0xfa, 0x95, 0xc4, 0x4c,
	0xb0, 0xea, 0x9b, 0x26, 0x3e, 0x2e, 0x35, 0x49,
	0x23, 0xb5, 0x96, 0xa1, 0x8c, 0xed, 0x52, 0x28,
	0xb3, 0x7a, 0xa9, 0xc9, 0xc3, 0x2a, 0x89, 0x96,
	0xb4, 0xb7, 0x22, 0x3c, 0x72, 0x87, 0x7f, 0x9f,
	0x59, 0x81, 0xe3, 0x9a, 0x27, 0xf2, 0x8c, 0x05,
};

/* ── TC3: different password and salt ────────────────────────────────────── */
/*
 * password   = "hunter42" (8 bytes)
 * salt       = "deadbeefdeadbeef" (16 bytes)
 * iterations = 2000
 * dkLen      = 64
 * DK         = 4ddf3cc0ff76477d7af3b66561d44d78
 *              8d60633eef64c68408c4386bc5a15cca
 *              96d0993556c33a91566ead8f19aeb57b
 *              9110bf307e0fd4c4cb154829ec2b78d1
 *
 * Verified: Python hashlib + OpenSSL 3 agree.
 */
static const unsigned char pbkdf2_sha512_tc3_password[] = "hunter42";
static const unsigned char pbkdf2_sha512_tc3_salt[]     = "deadbeefdeadbeef";
static const unsigned char pbkdf2_sha512_tc3_dk[] = {
	0x4d, 0xdf, 0x3c, 0xc0, 0xff, 0x76, 0x47, 0x7d,
	0x7a, 0xf3, 0xb6, 0x65, 0x61, 0xd4, 0x4d, 0x78,
	0x8d, 0x60, 0x63, 0x3e, 0xef, 0x64, 0xc6, 0x84,
	0x08, 0xc4, 0x38, 0x6b, 0xc5, 0xa1, 0x5c, 0xca,
	0x96, 0xd0, 0x99, 0x35, 0x56, 0xc3, 0x3a, 0x91,
	0x56, 0x6e, 0xad, 0x8f, 0x19, 0xae, 0xb5, 0x7b,
	0x91, 0x10, 0xbf, 0x30, 0x7e, 0x0f, 0xd4, 0xc4,
	0xcb, 0x15, 0x48, 0x29, 0xec, 0x2b, 0x78, 0xd1,
};

/* ── Vector table ───────────────────────────────────────────────────────── */

static const struct pbkdf2_sha512_vector pbkdf2_sha512_vectors[] = {
	{
		.password     = pbkdf2_sha512_tc1_password,
		.password_len = 8,   /* "password", no NUL */
		.salt         = pbkdf2_sha512_tc1_salt,
		.salt_len     = 16,  /* "saltsaltsaltsalt", no NUL */
		.iterations   = 1000,
		.dk_len       = sizeof(pbkdf2_sha512_tc1_dk),
		.dk           = pbkdf2_sha512_tc1_dk,
		.source       = "PBKDF2-HMAC-SHA512: pw=password salt=saltsaltsaltsalt iter=1000",
	},
	{
		.password     = pbkdf2_sha512_tc2_password,
		.password_len = 24,  /* "passwordPASSWORDpassword", no NUL */
		.salt         = pbkdf2_sha512_tc2_salt,
		.salt_len     = 24,  /* "saltSALTsaltSALTsaltSALT", no NUL */
		.iterations   = 4096,
		.dk_len       = sizeof(pbkdf2_sha512_tc2_dk),
		.dk           = pbkdf2_sha512_tc2_dk,
		.source       = "PBKDF2-HMAC-SHA512: pw=passwordPASSWORDpassword iter=4096",
	},
	{
		.password     = pbkdf2_sha512_tc3_password,
		.password_len = 8,   /* "hunter42", no NUL */
		.salt         = pbkdf2_sha512_tc3_salt,
		.salt_len     = 16,  /* "deadbeefdeadbeef", no NUL */
		.iterations   = 2000,
		.dk_len       = sizeof(pbkdf2_sha512_tc3_dk),
		.dk           = pbkdf2_sha512_tc3_dk,
		.source       = "PBKDF2-HMAC-SHA512: pw=hunter42 salt=deadbeefdeadbeef iter=2000",
	},
};

#define PBKDF2_SHA512_VECTOR_COUNT \
	(sizeof(pbkdf2_sha512_vectors) / sizeof(pbkdf2_sha512_vectors[0]))

#endif /* CRYPTO2DEV_VECTORS_PBKDF2_SHA512_H */
