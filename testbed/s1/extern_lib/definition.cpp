/*
 * P4ICS crypto externs for bmv2 (simple_switch --load-modules=definition.so).
 *
 * Each extern receives the whole application payload as the parser produced
 * it -- the valid 256-byte slices of the header stack followed by the varbit
 * tail -- gathers it into a byte buffer, transforms it, and scatters the
 * result back with its exact length. A single primitive thus serves every
 * payload size, instead of one primitive per number of slices.
 *
 * P4ICS v2 (all integers big endian, L plaintext bytes):
 *   K       = k1 .. kNk, the key words (p4ics_keys) before the first zero word (Nk = 4..8)
 *   enc_key = HKDF-SHA256(K, salt "P4ICS-v2", info "P4ICS-v2 enc", 4 * Nk)
 *   mac_key = HKDF-SHA256(K, salt "P4ICS-v2", info "P4ICS-v2 mac", 32)
 *   IV      = AES(enc_key, spi || 0^4 || counter)
 *   ct      = AES-CBC(enc_key, IV, plaintext || 1..16 zero bytes)
 *   aad     = "P4ICS-v2" || spi || counter || L || IPv4 src, dst
 *             || TCP ports, seq || industrial header
 *   tag     = HMAC-SHA256(mac_key, aad || ct)[0:16]        (encrypt-then-MAC)
 * savedLen = L, spi, counter and tag travel in the IPv4 options.
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
constexpr size_t kTagBytes = 16;        // HMAC-SHA256 truncated to 128 bits
constexpr int kKeyWords = 8;

// Fields of ipv4_options_t, in declaration order.
constexpr int kOptSavedLen = 0, kOptSpi = 1, kOptCounter = 2, kOptTag = 3;

const char kLabel[] = "P4ICS-v2";
const char kEncInfo[] = "P4ICS-v2 enc";
const char kMacInfo[] = "P4ICS-v2 mac";

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

// RFC 5869 with SHA-256, for length <= 32 (a single expand block).
void hkdf_sha256(const unsigned char *ikm, size_t ikm_len, const char *info, unsigned char *out,
                 size_t len) {
    unsigned char prk[32], block[32];
    Bytes msg(info, info + strlen(info));

    hmac_sha256(reinterpret_cast<const unsigned char *>(kLabel), strlen(kLabel), ikm, ikm_len, prk);
    msg.push_back(0x01);
    hmac_sha256(prk, sizeof(prk), msg.data(), msg.size(), block);
    memcpy(out, block, len);
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

Bytes deparse(const bm::Header &h) {
    Bytes out(static_cast<size_t>(h.get_nbytes_packet()));
    h.deparse(reinterpret_cast<char *>(out.data()));
    return out;
}

// What the tag binds besides the ciphertext.
Bytes mac_context(__u32 spi, uint64_t counter, uint64_t plain_len, const bm::Header &ipv4,
                  const bm::Header &tcp, const bm::Header *industrial) {
    Bytes aad(kLabel, kLabel + strlen(kLabel));
    unsigned char fields[16];
    Bytes ip = deparse(ipv4), l4 = deparse(tcp);

    P4ICS_PUTU32(fields, spi);
    P4ICS_PUTU32(fields + 4, static_cast<__u32>(counter >> 32));
    P4ICS_PUTU32(fields + 8, static_cast<__u32>(counter));
    P4ICS_PUTU32(fields + 12, static_cast<__u32>(plain_len));
    aad.insert(aad.end(), fields, fields + sizeof(fields));
    aad.insert(aad.end(), ip.begin() + 12, ip.begin() + 20);    // source, destination
    aad.insert(aad.end(), l4.begin(), l4.begin() + 8);          // ports, sequence number
    if (industrial) {
        Bytes h = deparse(*industrial);
        aad.insert(aad.end(), h.begin(), h.end());
    }
    return aad;
}

const bm::Header *industrial_header(const bm::Header &modbus, const bm::Header &mqtt,
                                    const bm::Header &cip, const bm::Header &dnp3) {
    for (const bm::Header *h : {&modbus, &mqtt, &cip, &dnp3})
        if (h->is_valid())
            return h;
    return nullptr;
}

// ---- Keys and per-packet crypto ---------------------------------------------

struct KeyMaterial {
    __u32 words[kKeyWords];
    __u32 nr;
    __u32 enc_rk[P4ICS_AES_RK_WORDS];
    __u32 dec_rk[P4ICS_AES_RK_WORDS];
    unsigned char mac_key[32];
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
    unsigned char enc_key[4 * kKeyWords];
    size_t key_len = 4 * static_cast<size_t>(nk);
    hkdf_sha256(raw.data(), key_len, kEncInfo, enc_key, key_len);
    hkdf_sha256(raw.data(), key_len, kMacInfo, cache.mac_key, sizeof(cache.mac_key));
    cache.nr = p4ics_aes_expand_key(enc_key, static_cast<__u32>(nk), cache.enc_rk, cache.dec_rk);
    memcpy(cache.words, words, sizeof(words));
    cache.valid = true;
    return &cache;
}

// IV = AES(enc_key, spi || 0^4 || counter): unpredictable and unique per packet.
void packet_iv(const KeyMaterial &k, __u32 spi, uint64_t counter, unsigned char iv[P4ICS_AES_BLOCK]) {
    __u32 s[4] = { spi, 0, static_cast<__u32>(counter >> 32), static_cast<__u32>(counter) };

    p4ics_aes_encrypt_words(k.enc_rk, k.nr, s);
    for (int i = 0; i < 4; i++)
        P4ICS_PUTU32(iv + 4 * i, s[i]);
}

void mac_tag(const KeyMaterial &k, const Bytes &aad, const Bytes &ct, unsigned char tag[kTagBytes]) {
    Bytes msg(aad);
    unsigned char mac[32];

    msg.insert(msg.end(), ct.begin(), ct.end());
    hmac_sha256(k.mac_key, sizeof(k.mac_key), msg.data(), msg.size(), mac);
    memcpy(tag, mac, kTagBytes);
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

void p4ics_cipher(bm::HeaderStack &slices, bm::Header &tail, bm::Header &opts,
                  const bm::Header &ipv4, const bm::Header &tcp, const bm::Header &modbus,
                  const bm::Header &mqtt, const bm::Header &cip, const bm::Header &dnp3,
                  const bm::Data &key, bm::Data &done) {
    const KeyMaterial *k = key_material(key);
    unsigned char iv[P4ICS_AES_BLOCK], tag[kTagBytes];

    done.set(0);
    if (!k)
        return;
    __u32 spi = static_cast<__u32>(opts.get_field(kOptSpi).get_uint64());
    uint64_t counter = opts.get_field(kOptCounter).get_uint64();
    Bytes data = gather(slices, tail);
    size_t plain_len = data.size();

    packet_iv(*k, spi, counter, iv);
    data.resize(crypt_len(plain_len), 0);   // zero padding, 1..16 bytes
    cbc(*k, true, iv, data);
    mac_tag(*k, mac_context(spi, counter, plain_len, ipv4, tcp,
                            industrial_header(modbus, mqtt, cip, dnp3)), data, tag);
    if (!scatter(slices, tail, data))
        return;
    opts.get_field(kOptSavedLen).set(static_cast<uint64_t>(plain_len));
    opts.get_field(kOptTag).set(reinterpret_cast<const char *>(tag), sizeof(tag));
    done.set(1);
}

void p4ics_decipher(bm::HeaderStack &slices, bm::Header &tail, const bm::Header &opts,
                    const bm::Header &ipv4, const bm::Header &tcp, const bm::Header &modbus,
                    const bm::Header &mqtt, const bm::Header &cip, const bm::Header &dnp3,
                    const bm::Data &key, bm::Data &verified) {
    const KeyMaterial *k = key_material(key);
    unsigned char iv[P4ICS_AES_BLOCK], tag[kTagBytes];
    unsigned char diff = 0;

    verified.set(0);
    if (!k)
        return;
    uint64_t plain_len = opts.get_field(kOptSavedLen).get_uint64();
    __u32 spi = static_cast<__u32>(opts.get_field(kOptSpi).get_uint64());
    uint64_t counter = opts.get_field(kOptCounter).get_uint64();
    Bytes data = gather(slices, tail);
    if (plain_len >= data.size() || data.size() != crypt_len(plain_len))
        return;

    // Encrypt-then-MAC: authenticate the ciphertext before decrypting it.
    mac_tag(*k, mac_context(spi, counter, plain_len, ipv4, tcp,
                            industrial_header(modbus, mqtt, cip, dnp3)), data, tag);
    Bytes received = data_bytes(opts.get_field(kOptTag), kTagBytes);
    for (size_t i = 0; i < kTagBytes; i++)
        diff |= tag[i] ^ received[i];
    if (diff)
        return;

    packet_iv(*k, spi, counter, iv);
    cbc(*k, false, iv, data);
    data.resize(plain_len);
    if (!scatter(slices, tail, data))
        return;
    verified.set(1);
}

BM_REGISTER_EXTERN_FUNCTION(p4ics_cipher, bm::HeaderStack &, bm::Header &, bm::Header &,
                            const bm::Header &, const bm::Header &, const bm::Header &,
                            const bm::Header &, const bm::Header &, const bm::Header &,
                            const bm::Data &, bm::Data &);
BM_REGISTER_EXTERN_FUNCTION(p4ics_decipher, bm::HeaderStack &, bm::Header &, const bm::Header &,
                            const bm::Header &, const bm::Header &, const bm::Header &,
                            const bm::Header &, const bm::Header &, const bm::Header &,
                            const bm::Data &, bm::Data &);
