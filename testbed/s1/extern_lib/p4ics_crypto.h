/*
 * Portable AES (Rijndael, Nb = 4, Nk = 4..8) and SHA-256 compression for the
 * P4ICS externs.
 *
 * Plain C without libc: loops have constant upper bounds and every table
 * index is masked to 0..255.
 *
 * The AES key schedule is the FIPS-197 one generalised to Nk = 5 and 7
 * (160/224-bit keys), as accepted by the `keys` register.
 */
#ifndef P4ICS_CRYPTO_H
#define P4ICS_CRYPTO_H

#include <linux/types.h>
#include "p4ics_aes_tables.h"

#define P4ICS_AES_BLOCK		16
#define P4ICS_AES_MIN_ROUNDS	10	/* Nk = 4 */
#define P4ICS_AES_MAX_ROUNDS	14	/* Nk = 8 */
#define P4ICS_AES_RK_WORDS	(4 * (P4ICS_AES_MAX_ROUNDS + 1))

#ifndef P4ICS_INLINE
#define P4ICS_INLINE static inline __attribute__((always_inline))
#endif

#define P4ICS_GETU32(p) \
	(((__u32)(p)[0] << 24) | ((__u32)(p)[1] << 16) | ((__u32)(p)[2] << 8) | (__u32)(p)[3])
#define P4ICS_PUTU32(p, v) do {			\
		(p)[0] = (__u8)((v) >> 24);	\
		(p)[1] = (__u8)((v) >> 16);	\
		(p)[2] = (__u8)((v) >> 8);	\
		(p)[3] = (__u8)(v);		\
	} while (0)

#define P4ICS_B0(x) ((x) >> 24)
#define P4ICS_B1(x) (((x) >> 16) & 0xff)
#define P4ICS_B2(x) (((x) >> 8) & 0xff)
#define P4ICS_B3(x) ((x) & 0xff)

/* ---- AES ------------------------------------------------------------------ */

/* Encrypt one block held as 4 big-endian column words; nr must be 10..14. */
P4ICS_INLINE void p4ics_aes_encrypt_words(const __u32 *rk, __u32 nr, __u32 *s)
{
	__u32 s0 = s[0] ^ rk[0], s1 = s[1] ^ rk[1];
	__u32 s2 = s[2] ^ rk[2], s3 = s[3] ^ rk[3];
	__u32 t0, t1, t2, t3, r;
	const __u32 *k;

	for (r = 1; r < P4ICS_AES_MAX_ROUNDS; r++) {
		if (r >= nr)
			break;
		k = rk + 4 * r;
		t0 = p4ics_te0[P4ICS_B0(s0)] ^ p4ics_te1[P4ICS_B1(s1)] ^
		     p4ics_te2[P4ICS_B2(s2)] ^ p4ics_te3[P4ICS_B3(s3)] ^ k[0];
		t1 = p4ics_te0[P4ICS_B0(s1)] ^ p4ics_te1[P4ICS_B1(s2)] ^
		     p4ics_te2[P4ICS_B2(s3)] ^ p4ics_te3[P4ICS_B3(s0)] ^ k[1];
		t2 = p4ics_te0[P4ICS_B0(s2)] ^ p4ics_te1[P4ICS_B1(s3)] ^
		     p4ics_te2[P4ICS_B2(s0)] ^ p4ics_te3[P4ICS_B3(s1)] ^ k[2];
		t3 = p4ics_te0[P4ICS_B0(s3)] ^ p4ics_te1[P4ICS_B1(s0)] ^
		     p4ics_te2[P4ICS_B2(s1)] ^ p4ics_te3[P4ICS_B3(s2)] ^ k[3];
		s0 = t0; s1 = t1; s2 = t2; s3 = t3;
	}

	k = rk + 4 * nr;
	s[0] = ((__u32)p4ics_sbox[P4ICS_B0(s0)] << 24) ^ ((__u32)p4ics_sbox[P4ICS_B1(s1)] << 16) ^
	       ((__u32)p4ics_sbox[P4ICS_B2(s2)] << 8) ^ (__u32)p4ics_sbox[P4ICS_B3(s3)] ^ k[0];
	s[1] = ((__u32)p4ics_sbox[P4ICS_B0(s1)] << 24) ^ ((__u32)p4ics_sbox[P4ICS_B1(s2)] << 16) ^
	       ((__u32)p4ics_sbox[P4ICS_B2(s3)] << 8) ^ (__u32)p4ics_sbox[P4ICS_B3(s0)] ^ k[1];
	s[2] = ((__u32)p4ics_sbox[P4ICS_B0(s2)] << 24) ^ ((__u32)p4ics_sbox[P4ICS_B1(s3)] << 16) ^
	       ((__u32)p4ics_sbox[P4ICS_B2(s0)] << 8) ^ (__u32)p4ics_sbox[P4ICS_B3(s1)] ^ k[2];
	s[3] = ((__u32)p4ics_sbox[P4ICS_B0(s3)] << 24) ^ ((__u32)p4ics_sbox[P4ICS_B1(s0)] << 16) ^
	       ((__u32)p4ics_sbox[P4ICS_B2(s1)] << 8) ^ (__u32)p4ics_sbox[P4ICS_B3(s2)] ^ k[3];
}

/* Decrypt one block with the equivalent-inverse-cipher schedule (dec_rk). */
P4ICS_INLINE void p4ics_aes_decrypt_words(const __u32 *rk, __u32 nr, __u32 *s)
{
	__u32 s0 = s[0] ^ rk[0], s1 = s[1] ^ rk[1];
	__u32 s2 = s[2] ^ rk[2], s3 = s[3] ^ rk[3];
	__u32 t0, t1, t2, t3, r;
	const __u32 *k;

	for (r = 1; r < P4ICS_AES_MAX_ROUNDS; r++) {
		if (r >= nr)
			break;
		k = rk + 4 * r;
		t0 = p4ics_td0[P4ICS_B0(s0)] ^ p4ics_td1[P4ICS_B1(s3)] ^
		     p4ics_td2[P4ICS_B2(s2)] ^ p4ics_td3[P4ICS_B3(s1)] ^ k[0];
		t1 = p4ics_td0[P4ICS_B0(s1)] ^ p4ics_td1[P4ICS_B1(s0)] ^
		     p4ics_td2[P4ICS_B2(s3)] ^ p4ics_td3[P4ICS_B3(s2)] ^ k[1];
		t2 = p4ics_td0[P4ICS_B0(s2)] ^ p4ics_td1[P4ICS_B1(s1)] ^
		     p4ics_td2[P4ICS_B2(s0)] ^ p4ics_td3[P4ICS_B3(s3)] ^ k[2];
		t3 = p4ics_td0[P4ICS_B0(s3)] ^ p4ics_td1[P4ICS_B1(s2)] ^
		     p4ics_td2[P4ICS_B2(s1)] ^ p4ics_td3[P4ICS_B3(s0)] ^ k[3];
		s0 = t0; s1 = t1; s2 = t2; s3 = t3;
	}

	k = rk + 4 * nr;
	s[0] = ((__u32)p4ics_inv_sbox[P4ICS_B0(s0)] << 24) ^ ((__u32)p4ics_inv_sbox[P4ICS_B1(s3)] << 16) ^
	       ((__u32)p4ics_inv_sbox[P4ICS_B2(s2)] << 8) ^ (__u32)p4ics_inv_sbox[P4ICS_B3(s1)] ^ k[0];
	s[1] = ((__u32)p4ics_inv_sbox[P4ICS_B0(s1)] << 24) ^ ((__u32)p4ics_inv_sbox[P4ICS_B1(s0)] << 16) ^
	       ((__u32)p4ics_inv_sbox[P4ICS_B2(s3)] << 8) ^ (__u32)p4ics_inv_sbox[P4ICS_B3(s2)] ^ k[1];
	s[2] = ((__u32)p4ics_inv_sbox[P4ICS_B0(s2)] << 24) ^ ((__u32)p4ics_inv_sbox[P4ICS_B1(s1)] << 16) ^
	       ((__u32)p4ics_inv_sbox[P4ICS_B2(s0)] << 8) ^ (__u32)p4ics_inv_sbox[P4ICS_B3(s3)] ^ k[2];
	s[3] = ((__u32)p4ics_inv_sbox[P4ICS_B0(s3)] << 24) ^ ((__u32)p4ics_inv_sbox[P4ICS_B1(s2)] << 16) ^
	       ((__u32)p4ics_inv_sbox[P4ICS_B2(s1)] << 8) ^ (__u32)p4ics_inv_sbox[P4ICS_B3(s0)] ^ k[3];
}

P4ICS_INLINE __u32 p4ics_aes_subword(__u32 w)
{
	return ((__u32)p4ics_sbox[P4ICS_B0(w)] << 24) | ((__u32)p4ics_sbox[P4ICS_B1(w)] << 16) |
	       ((__u32)p4ics_sbox[P4ICS_B2(w)] << 8) | (__u32)p4ics_sbox[P4ICS_B3(w)];
}

/*
 * Expand an Nk-word key (Nk = 4..8) into enc_rk and dec_rk.
 * Returns the number of rounds (Nk + 6), or 0 if nk is out of range.
 */
P4ICS_INLINE __u32 p4ics_aes_expand_key(const __u8 *key, __u32 nk, __u32 *enc_rk, __u32 *dec_rk)
{
	__u32 nr = nk + 6, total, i, r, c, t, rcon = 1;

	if (nk < 4 || nk > 8)
		return 0;
	total = 4 * (nr + 1);
	for (i = 0; i < nk; i++)
		enc_rk[i] = P4ICS_GETU32(key + 4 * i);
	for (i = nk; i < total; i++) {
		t = enc_rk[i - 1];
		if (i % nk == 0) {
			t = p4ics_aes_subword((t << 8) | (t >> 24)) ^ (rcon << 24);
			rcon = (rcon << 1) ^ ((rcon & 0x80) ? 0x11b : 0);
		} else if (nk > 6 && i % nk == 4) {
			t = p4ics_aes_subword(t);
		}
		enc_rk[i] = enc_rk[i - nk] ^ t;
	}

	/* Equivalent inverse cipher: reverse the rounds, InvMixColumns 1..nr-1. */
	for (r = 0; r <= nr; r++)
		for (c = 0; c < 4; c++)
			dec_rk[4 * r + c] = enc_rk[4 * (nr - r) + c];
	for (r = 1; r < nr; r++) {
		for (c = 0; c < 4; c++) {
			t = dec_rk[4 * r + c];
			dec_rk[4 * r + c] = p4ics_td0[p4ics_sbox[P4ICS_B0(t)]] ^
					    p4ics_td1[p4ics_sbox[P4ICS_B1(t)]] ^
					    p4ics_td2[p4ics_sbox[P4ICS_B2(t)]] ^
					    p4ics_td3[p4ics_sbox[P4ICS_B3(t)]];
		}
	}
	return nr;
}

/* ---- SHA-256 -------------------------------------------------------------- */

static const __u32 p4ics_sha256_k[64] = {
	0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
	0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
	0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
	0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
	0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
	0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
	0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
	0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static const __u32 p4ics_sha256_iv[8] = {
	0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
	0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
};

#define P4ICS_ROR(x, n)	(((x) >> (n)) | ((x) << (32 - (n))))

/* Compress one block into h; w[0..15] must hold the block's big-endian words. */
P4ICS_INLINE void p4ics_sha256_compress(__u32 *h, __u32 *w)
{
	__u32 a, b, c, d, e, f, g, hh, t1, t2, i;

	for (i = 16; i < 64; i++) {
		__u32 x = w[i - 15], y = w[i - 2];

		w[i] = w[i - 16] + w[i - 7] +
		       (P4ICS_ROR(x, 7) ^ P4ICS_ROR(x, 18) ^ (x >> 3)) +
		       (P4ICS_ROR(y, 17) ^ P4ICS_ROR(y, 19) ^ (y >> 10));
	}

	a = h[0]; b = h[1]; c = h[2]; d = h[3];
	e = h[4]; f = h[5]; g = h[6]; hh = h[7];
	for (i = 0; i < 64; i++) {
		t1 = hh + (P4ICS_ROR(e, 6) ^ P4ICS_ROR(e, 11) ^ P4ICS_ROR(e, 25)) +
		     ((e & f) ^ (~e & g)) + p4ics_sha256_k[i] + w[i];
		t2 = (P4ICS_ROR(a, 2) ^ P4ICS_ROR(a, 13) ^ P4ICS_ROR(a, 22)) +
		     ((a & b) ^ (a & c) ^ (b & c));
		hh = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}
	h[0] += a; h[1] += b; h[2] += c; h[3] += d;
	h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

#endif /* P4ICS_CRYPTO_H */
