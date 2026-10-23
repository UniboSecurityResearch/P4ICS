/*
 * P4ICS crypto externs, implemented in definition.cpp.
 *
 * The payload is passed as the parser left it: the header stack of 256-byte
 * slices plus the varbit tail. One primitive therefore covers every payload
 * size, and the result is written back with its exact length (re-packed into
 * slices + tail). Algorithms: see the header of definition.cpp.
 *
 * key: the 256-bit key of the frame's key phase (table p4ics_keys); the
 *      switch uses the 32-bit words before the first zero word.
 * opts: the P4ICS IPv4 options (savedLen, spi, counter, tag). The tag also
 * covers the addresses (ipv4), ports and sequence number (tcp) and the
 * industrial header, whichever of modbus/mqtt/cip/dnp3 is valid.
 */

// Plaintext -> AES-CBC ciphertext, then tag (encrypt-then-MAC). Reads
// opts.spi/opts.counter, writes opts.savedLen/opts.tag; done = 0 if the
// payload could not be protected.
extern void p4ics_cipher<S, T, O, I, P, M, Q, C, D, K, R>(
    inout S slices, inout T tail, inout O opts, in I ipv4, in P tcp,
    in M modbus, in Q mqtt, in C cip, in D dnp3, in K key, out R done);

// Verify the tag, then decrypt (verified = 1). The payload is left untouched
// if the tag or the lengths do not match.
extern void p4ics_decipher<S, T, O, I, P, M, Q, C, D, K, R>(
    inout S slices, inout T tail, in O opts, in I ipv4, in P tcp,
    in M modbus, in Q mqtt, in C cip, in D dnp3, in K key, out R verified);
