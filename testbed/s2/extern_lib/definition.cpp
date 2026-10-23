/*
 * P4ICS crypto externs for bmv2 (simple_switch --load-modules=definition.so).
 *
 * Each extern receives the whole application payload as the parser produced
 * it -- the valid 256-byte slices of the header stack followed by the varbit
 * tail -- gathers it into a byte buffer, transforms it, and scatters the
 * result back with its exact length. A single primitive thus serves every
 * payload size, instead of one primitive per number of slices.
 *
 * Protected payload (L plaintext bytes, seq = TCP sequence number, big endian):
 *   hk  = HMAC-SHA256(be32(k1) || be32(k2), "P4ICS-HMAC-KDF-v1")
 *   IV  = HMAC-SHA256(hk, "P4ICS-IV-v1" || seq)[0:16]
 *   tag = HMAC-SHA256(hk, "P4ICS-HMAC-PAYLOAD-v1" || seq || lower-case hex(plaintext))
 *   ct  = AES-CBC(key, IV, plaintext || 1..16 zero bytes)
 * The AES key is k1..kNk, the register words before the first zero word
 * (Nk = 4..8, Nr = Nk + 6). savedLen = L travels in the IPv4 options.
 */
#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/headers.h>
#include <bm/bm_sim/stacks.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "p4ics_crypto.h"

namespace {

using Bytes = std::vector<unsigned char>;

constexpr size_t kSliceBytes = 256;
constexpr size_t kTagBytes = 32;
constexpr int kKeyWords = 8;

const char kKdfLabel[] = "P4ICS-HMAC-KDF-v1";
const char kIvDomain[] = "P4ICS-IV-v1";
const char kMacDomain[] = "P4ICS-HMAC-PAYLOAD-v1";

size_t crypt_len(size_t plain_len) {
    return (plain_len / P4ICS_AES_BLOCK + 1) * P4ICS_AES_BLOCK;
}

// ---- SHA-256 / HMAC-SHA256 ------------------------------------------------

class Sha256 {
  public:
    Sha256() { memcpy(h_, p4ics_sha256_iv, sizeof(h_)); }

    void update(const unsigned char *p, size_t n) {
        total_ += n;
        while (n) {
            size_t k = std::min(n, sizeof(buf_) - fill_);
            memcpy(buf_ + fill_, p, k);
            fill_ += k;
            p += k;
            n -= k;
            if (fill_ == sizeof(buf_)) {
                block(buf_);
                fill_ = 0;
            }
        }
    }

    void final(unsigned char out[32]) {
        uint64_t bits = total_ * 8;
        unsigned char pad = 0x80, zero = 0, len[8];

        update(&pad, 1);
        while (fill_ != 56)
            update(&zero, 1);
        for (int i = 0; i < 8; i++)
            len[i] = static_cast<unsigned char>(bits >> (56 - 8 * i));
        update(len, 8);
        for (int i = 0; i < 8; i++)
            P4ICS_PUTU32(out + 4 * i, h_[i]);
    }

  private:
    void block(const unsigned char *b) {
        for (int i = 0; i < 16; i++)
            w_[i] = P4ICS_GETU32(b + 4 * i);
        p4ics_sha256_compress(h_, w_);
    }

    __u32 h_[8];
    __u32 w_[64];
    unsigned char buf_[64];
    size_t fill_ = 0;
    uint64_t total_ = 0;
};

void hmac_sha256(const unsigned char *key, size_t klen, const unsigned char *msg, size_t mlen,
                 unsigned char out[32]) {
    unsigned char k[64] = {0}, pad[64], inner[32];

    if (klen > sizeof(k)) {
        Sha256 s;
        s.update(key, klen);
        s.final(k);
    } else {
        memcpy(k, key, klen);
    }
    for (size_t i = 0; i < sizeof(k); i++)
        pad[i] = k[i] ^ 0x36;
    Sha256 in;
    in.update(pad, sizeof(pad));
    in.update(msg, mlen);
    in.final(inner);
    for (size_t i = 0; i < sizeof(k); i++)
        pad[i] = k[i] ^ 0x5c;
    Sha256 outer;
    outer.update(pad, sizeof(pad));
    outer.update(inner, sizeof(inner));
    outer.final(out);
}

// ---- Packet payload <-> bytes -----------------------------------------------

// Big-endian bytes of a value, left-padded to n (bmv2 strips leading zeros).
Bytes data_bytes(const bm::Data &d, size_t n) {
    std::string s = d.get_string();
    Bytes out(n, 0);
    if (s.size() >= n)
        memcpy(out.data(), s.data() + s.size() - n, n);
    else
        memcpy(out.data() + n - s.size(), s.data(), s.size());
    return out;
}

Bytes gather(const bm::HeaderStack &slices, const bm::Header &tail) {
    Bytes out;
    for (size_t i = 0; i < slices.get_depth(); i++) {
        const bm::Header &h = slices.at(i);
        if (!h.is_valid())
            continue;
        const bm::ByteContainer &b = h.get_field(0).get_bytes();
        out.insert(out.end(), b.data(), b.data() + b.size());
    }
    if (tail.is_valid()) {
        const bm::ByteContainer &b = tail.get_field(0).get_bytes();
        out.insert(out.end(), b.data(), b.data() + b.size());
    }
    return out;
}

// Write data back as full slices + a tail of the remaining bytes.
bool scatter(bm::HeaderStack &slices, bm::Header &tail, const Bytes &data) {
    size_t full = data.size() / kSliceBytes, rest = data.size() % kSliceBytes;
    const char *p = reinterpret_cast<const char *>(data.data());

    if (full > slices.get_depth())
        return false;
    for (size_t i = 0; i < slices.get_depth(); i++) {
        bm::Header &h = slices.at(i);
        if (i < full) {
            h.mark_valid();
            h.get_field(0).set_bytes(p + i * kSliceBytes, kSliceBytes);
        } else {
            h.mark_invalid();
        }
    }
    if (rest) {
        tail.mark_valid();
        tail.get_field(0).extract_VL(p + full * kSliceBytes, 0, static_cast<int>(rest * 8));
        tail.recompute_nbytes_packet();
    } else {
        tail.mark_invalid();
    }
    return true;
}

// ---- Keys and per-packet crypto ---------------------------------------------

struct KeyMaterial {
    __u32 words[kKeyWords];
    __u32 nr;
    __u32 enc_rk[P4ICS_AES_RK_WORDS];
    __u32 dec_rk[P4ICS_AES_RK_WORDS];
    unsigned char hk[32];   // HMAC key
    bool valid;
};

// Derived once per key: the words only change when the control plane rotates it.
const KeyMaterial *key_material(const bm::Data &key) {
    thread_local KeyMaterial cache{};
    Bytes raw = data_bytes(key, 4 * kKeyWords);
    __u32 words[kKeyWords];
    int nk = kKeyWords;

    for (int i = 0; i < kKeyWords; i++)
        words[i] = P4ICS_GETU32(raw.data() + 4 * i);
    if (cache.valid && !memcmp(words, cache.words, sizeof(words)))
        return &cache;
    for (int i = 0; i < kKeyWords; i++) {
        if (!words[i]) {
            nk = i;
            break;
        }
    }
    cache.valid = false;
    if (nk < 4)
        return nullptr;
    cache.nr = p4ics_aes_expand_key(raw.data(), static_cast<__u32>(nk), cache.enc_rk, cache.dec_rk);
    hmac_sha256(raw.data(), 8, reinterpret_cast<const unsigned char *>(kKdfLabel),
                strlen(kKdfLabel), cache.hk);
    memcpy(cache.words, words, sizeof(words));
    cache.valid = true;
    return &cache;
}

void packet_iv(const KeyMaterial &k, __u32 seq, unsigned char iv[P4ICS_AES_BLOCK]) {
    Bytes msg(kIvDomain, kIvDomain + strlen(kIvDomain));
    unsigned char mac[32];

    msg.resize(msg.size() + 4);
    P4ICS_PUTU32(msg.data() + msg.size() - 4, seq);
    hmac_sha256(k.hk, sizeof(k.hk), msg.data(), msg.size(), mac);
    memcpy(iv, mac, P4ICS_AES_BLOCK);
}

void payload_tag(const KeyMaterial &k, __u32 seq, const Bytes &plain, unsigned char tag[kTagBytes]) {
    static const char hex[] = "0123456789abcdef";
    Bytes msg(kMacDomain, kMacDomain + strlen(kMacDomain));

    msg.resize(msg.size() + 4);
    P4ICS_PUTU32(msg.data() + msg.size() - 4, seq);
    for (unsigned char b : plain) {
        msg.push_back(static_cast<unsigned char>(hex[b >> 4]));
        msg.push_back(static_cast<unsigned char>(hex[b & 0x0f]));
    }
    hmac_sha256(k.hk, sizeof(k.hk), msg.data(), msg.size(), tag);
}

void cbc(const KeyMaterial &k, bool encrypt, const unsigned char iv[P4ICS_AES_BLOCK], Bytes &data) {
    __u32 prev[4], s[4], c[4];

    for (int i = 0; i < 4; i++)
        prev[i] = P4ICS_GETU32(iv + 4 * i);
    for (size_t off = 0; off < data.size(); off += P4ICS_AES_BLOCK) {
        unsigned char *b = data.data() + off;
        for (int i = 0; i < 4; i++)
            c[i] = s[i] = P4ICS_GETU32(b + 4 * i);
        if (encrypt) {
            for (int i = 0; i < 4; i++)
                s[i] ^= prev[i];
            p4ics_aes_encrypt_words(k.enc_rk, k.nr, s);
            memcpy(prev, s, sizeof(prev));
        } else {
            p4ics_aes_decrypt_words(k.dec_rk, k.nr, s);
            for (int i = 0; i < 4; i++)
                s[i] ^= prev[i];
            memcpy(prev, c, sizeof(prev));
        }
        for (int i = 0; i < 4; i++)
            P4ICS_PUTU32(b + 4 * i, s[i]);
    }
}

}  // namespace

void p4ics_cipher(bm::HeaderStack &slices, bm::Header &tail, bm::Data &saved_len,
                  bm::Data &tag, const bm::Data &seq_no, const bm::Data &key, bm::Data &done) {
    const KeyMaterial *k = key_material(key);
    __u32 seq = static_cast<__u32>(seq_no.get_uint64());
    unsigned char iv[P4ICS_AES_BLOCK], mac[kTagBytes];

    done.set(0);
    if (!k)
        return;
    Bytes data = gather(slices, tail);
    size_t plain_len = data.size();

    payload_tag(*k, seq, data, mac);
    packet_iv(*k, seq, iv);
    data.resize(crypt_len(plain_len), 0);   // zero padding, 1..16 bytes
    cbc(*k, true, iv, data);
    if (!scatter(slices, tail, data))
        return;
    saved_len.set(static_cast<uint64_t>(plain_len));
    tag.set(reinterpret_cast<const char *>(mac), sizeof(mac));
    done.set(1);
}

void p4ics_decipher(bm::HeaderStack &slices, bm::Header &tail, const bm::Data &saved_len,
                    const bm::Data &tag, const bm::Data &seq_no, const bm::Data &key,
                    bm::Data &verified) {
    const KeyMaterial *k = key_material(key);
    __u32 seq = static_cast<__u32>(seq_no.get_uint64());
    unsigned char iv[P4ICS_AES_BLOCK], mac[kTagBytes];
    unsigned char diff = 0;

    verified.set(0);
    if (!k)
        return;
    Bytes data = gather(slices, tail);
    uint64_t plain_len = saved_len.get_uint64();
    if (plain_len >= data.size() || data.size() != crypt_len(plain_len))
        return;

    packet_iv(*k, seq, iv);
    cbc(*k, false, iv, data);
    data.resize(plain_len);
    payload_tag(*k, seq, data, mac);
    Bytes received = data_bytes(tag, kTagBytes);
    for (size_t i = 0; i < kTagBytes; i++)
        diff |= mac[i] ^ received[i];
    if (diff || !scatter(slices, tail, data))
        return;
    verified.set(1);
}

BM_REGISTER_EXTERN_FUNCTION(p4ics_cipher, bm::HeaderStack &, bm::Header &, bm::Data &, bm::Data &,
                            const bm::Data &, const bm::Data &, bm::Data &);
BM_REGISTER_EXTERN_FUNCTION(p4ics_decipher, bm::HeaderStack &, bm::Header &, const bm::Data &,
                            const bm::Data &, const bm::Data &, const bm::Data &, bm::Data &);
