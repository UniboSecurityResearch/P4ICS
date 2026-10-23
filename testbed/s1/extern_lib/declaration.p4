/*
 * P4ICS crypto externs, implemented in definition.cpp.
 *
 * The payload is passed as the parser left it: the header stack of 256-byte
 * slices plus the varbit tail. One primitive therefore covers every payload
 * size, and the result is written back with its exact length (re-packed into
 * slices + tail). Algorithms: see the header of definition.cpp.
 *
 * key: the 8 words of the `keys` register, k1 first (k1 ++ ... ++ k8).
 */

// Plaintext -> AES-CBC ciphertext. savedLen = plaintext length,
// tag = HMAC-SHA256 tag; done = 0 if the payload could not be protected.
extern void p4ics_cipher<S, T, L, H, Q, K, R>(inout S slices, inout T tail, out L savedLen,
                                             out H tag, in Q seqNo, in K key, out R done);

// Ciphertext -> plaintext, only if the tag verifies (verified = 1); the
// payload is left untouched otherwise.
extern void p4ics_decipher<S, T, L, H, Q, K, R>(inout S slices, inout T tail, in L savedLen,
                                               in H tag, in Q seqNo, in K key, out R verified);
