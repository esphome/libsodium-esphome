/*
 * Known-answer and differential tests for the patched tree.
 *
 * 1. The reference AEAD must reproduce the RFC 8439 section 2.8.2 vector.
 * 2. The ESPHome session fast path (crypto_stream_chacha20_ietf_session_*
 *    plus crypto_onetimeauth_poly1305_aead_mac) must be byte identical to
 *    crypto_aead_chacha20poly1305_ietf_encrypt_detached across a sweep of
 *    payload and ad lengths.
 * 3. A block0-only call must leave the session counter so that a following
 *    session_xor produces the same ciphertext as the fused call.
 * 4. X25519 must reproduce the RFC 7748 vectors (including the iterated
 *    one), both through the library and through the ESP8266 m15 ladder in
 *    port/x25519_m15.c, and the ladder must agree with the library on
 *    random inputs. Built with SODIUM_ESPHOME_TEST_ESP8266_PATHS the
 *    library itself runs the ESP8266 code (patches 08 and 09), so the same
 *    vectors cover that build too.
 *
 * Build against the patched submodule (run pack.sh style patch application
 * first); see .github/workflows/ci.yml.
 */

#include <stdio.h>
#include <string.h>

#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_hash_sha256.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_stream_chacha20.h>
#include <sodium/randombytes.h>

#include <sodium/esphome_x25519_m15.h>

#if defined(__has_include)
# if __has_include(<sodium/sodium_esphome.h>)
#  include <sodium/sodium_esphome.h>
# endif
#endif

static int failures = 0;

static void check(int ok, const char *what)
{
    if (!ok) {
        printf("FAIL: %s\n", what);
        failures++;
    }
}

static const unsigned char kat_key[32] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
};

/* RFC 8439 section 2.8.2: nonce = 0x07 00 00 00 | 0x40..0x47 */
static const unsigned char kat_npub[12] = {
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
};

static const unsigned char kat_ad[12] = {
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
};

static const char kat_msg[] =
    "Ladies and Gentlemen of the class of '99: "
    "If I could offer you only one tip for the future, sunscreen would be it.";

static const unsigned char kat_ct[114] = {
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc,
    0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
    0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e,
    0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
    0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
    0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
    0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65,
    0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16
};

static const unsigned char kat_tag[16] = {
    0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
    0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
};

static void test_rfc8439_kat(void)
{
    unsigned char c[114];
    unsigned char mac[16];
    unsigned long long maclen;

    crypto_aead_chacha20poly1305_ietf_encrypt_detached(
        c, mac, &maclen, (const unsigned char *) kat_msg, 114,
        kat_ad, 12, NULL, kat_npub, kat_key);
    check(maclen == 16, "kat maclen");
    check(memcmp(c, kat_ct, sizeof kat_ct) == 0, "kat ciphertext");
    check(memcmp(mac, kat_tag, sizeof kat_tag) == 0, "kat tag");
}

#ifdef SODIUM_ESPHOME_NOISE_FAST_PATH
static void test_session_differential(void)
{
    static const size_t adlens[] = { 0, 1, 12, 15, 16, 17, 40 };
    unsigned char m[131];
    unsigned char ad[40];
    unsigned char ref_c[131];
    unsigned char ref_mac[16];
    unsigned char fast_c[131];
    unsigned char fast_mac[16];
    unsigned char block0[64];
    unsigned char npub[12];
    unsigned long long maclen;
    crypto_stream_chacha20_ietf_session_state st;
    uint64_t nonce64;
    size_t clen, a, i;
    char what[64];

    for (i = 0; i < sizeof m; i++) {
        m[i] = (unsigned char) (i * 7 + 1);
    }
    for (i = 0; i < sizeof ad; i++) {
        ad[i] = (unsigned char) (0xc0 ^ i);
    }
    /* nonce with all bytes distinct; 4 zero prefix per the Noise layout */
    nonce64 = 0x0807060504030201ULL;
    memset(npub, 0, 4);
    for (i = 0; i < 8; i++) {
        npub[4 + i] = (unsigned char) (nonce64 >> (8 * i));
    }

    crypto_stream_chacha20_ietf_session_init(&st, kat_key);

    for (clen = 0; clen <= 130; clen++) {
        for (a = 0; a < sizeof adlens / sizeof adlens[0]; a++) {
            crypto_aead_chacha20poly1305_ietf_encrypt_detached(
                ref_c, ref_mac, &maclen, m, clen,
                adlens[a] ? ad : NULL, adlens[a], NULL, npub, kat_key);

            crypto_stream_chacha20_ietf_session_block0_xor(
                &st, block0, fast_c, m, clen, nonce64);
            crypto_onetimeauth_poly1305_aead_mac(
                fast_mac, adlens[a] ? ad : NULL, adlens[a],
                fast_c, clen, block0);

            snprintf(what, sizeof what, "differential clen=%zu adlen=%zu",
                     clen, adlens[a]);
            check(memcmp(ref_c, fast_c, clen) == 0 &&
                  memcmp(ref_mac, fast_mac, 16) == 0, what);
        }
    }
}

static void test_session_counter_continuation(void)
{
    unsigned char fused_c[131];
    unsigned char split_c[131];
    unsigned char m[131];
    unsigned char block0_a[64];
    unsigned char block0_b[64];
    crypto_stream_chacha20_ietf_session_state st;
    size_t i;

    for (i = 0; i < sizeof m; i++) {
        m[i] = (unsigned char) (i ^ 0x5a);
    }
    crypto_stream_chacha20_ietf_session_init(&st, kat_key);
    crypto_stream_chacha20_ietf_session_block0_xor(
        &st, block0_a, fused_c, m, sizeof m, 42);

    /* block0-only call, then continue the payload from counter 1 */
    crypto_stream_chacha20_ietf_session_block0_xor(
        &st, block0_b, NULL, NULL, 0, 42);
    crypto_stream_chacha20_ietf_session_xor(&st, split_c, m, sizeof m);

    check(memcmp(block0_a, block0_b, 64) == 0, "block0 stable");
    check(memcmp(fused_c, split_c, sizeof m) == 0, "counter continuation");
}

#endif /* SODIUM_ESPHOME_NOISE_FAST_PATH */

/* RFC 7748 section 5.2 and 6.1 vectors */
static const unsigned char x25519_scalar1[32] = {
    0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15,
    0x4b, 0x82, 0x46, 0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc,
    0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4
};
static const unsigned char x25519_u1[32] = {
    0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1,
    0xa4, 0x24, 0xb1, 0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3,
    0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c
};
static const unsigned char x25519_out1[32] = {
    0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea,
    0x4d, 0xf2, 0x8d, 0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c,
    0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52
};
static const unsigned char x25519_scalar2[32] = {
    0x4b, 0x66, 0xe9, 0xd4, 0xd1, 0xb4, 0x67, 0x3c, 0x5a, 0xd2, 0x26,
    0x91, 0x95, 0x7d, 0x6a, 0xf5, 0xc1, 0x1b, 0x64, 0x21, 0xe0, 0xea,
    0x01, 0xd4, 0x2c, 0xa4, 0x16, 0x9e, 0x79, 0x18, 0xba, 0x0d
};
static const unsigned char x25519_u2[32] = {
    0xe5, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3, 0xf4, 0xb7, 0x95,
    0x9d, 0x05, 0x38, 0xae, 0x2c, 0x31, 0xdb, 0xe7, 0x10, 0x6f, 0xc0,
    0x3c, 0x3e, 0xfc, 0x4c, 0xd5, 0x49, 0xc7, 0x15, 0xa4, 0x93
};
static const unsigned char x25519_out2[32] = {
    0x95, 0xcb, 0xde, 0x94, 0x76, 0xe8, 0x90, 0x7d, 0x7a, 0xad, 0xe4,
    0x5c, 0xb4, 0xb8, 0x73, 0xf8, 0x8b, 0x59, 0x5a, 0x68, 0x79, 0x9f,
    0xa1, 0x52, 0xe6, 0xf8, 0xf7, 0x64, 0x7a, 0xac, 0x79, 0x57
};
static const unsigned char x25519_iter1[32] = {
    0x42, 0x2c, 0x8e, 0x7a, 0x62, 0x27, 0xd7, 0xbc, 0xa1, 0x35, 0x0b,
    0x3e, 0x2b, 0xb7, 0x27, 0x9f, 0x78, 0x97, 0xb8, 0x7b, 0xb6, 0x85,
    0x4b, 0x78, 0x3c, 0x60, 0xe8, 0x03, 0x11, 0xae, 0x30, 0x79
};
static const unsigned char x25519_iter1000[32] = {
    0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55, 0x28, 0x00, 0xef,
    0x56, 0x6f, 0x2f, 0x4d, 0x3c, 0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60,
    0xe3, 0x87, 0x5f, 0x2e, 0xb9, 0x4d, 0x99, 0x53, 0x2c, 0x51
};
static const unsigned char x25519_alice_priv[32] = {
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
    0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
    0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
};
static const unsigned char x25519_alice_pub[32] = {
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d,
    0xdc, 0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38,
    0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
};
static const unsigned char x25519_bob_priv[32] = {
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f,
    0x8b, 0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18,
    0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
};
static const unsigned char x25519_bob_pub[32] = {
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61,
    0xc2, 0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78,
    0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
};
static const unsigned char x25519_shared[32] = {
    0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b,
    0xf4, 0x80, 0x35, 0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1,
    0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42
};

static const unsigned char x25519_basepoint[32] = { 9 };

typedef int (*x25519_fn)(unsigned char *, const unsigned char *, const unsigned char *);

static void test_x25519_vectors(x25519_fn fn, const char *name)
{
    static const struct {
        const unsigned char *k, *u, *expected;
    } vectors[] = {
        { x25519_scalar1, x25519_u1, x25519_out1 },
        { x25519_scalar2, x25519_u2, x25519_out2 },
        { x25519_alice_priv, x25519_bob_pub, x25519_shared },
        { x25519_bob_priv, x25519_alice_pub, x25519_shared },
        { x25519_alice_priv, x25519_basepoint, x25519_alice_pub },
        { x25519_bob_priv, x25519_basepoint, x25519_bob_pub },
    };
    unsigned char out[32], k[32], u[32];
    size_t v;
    int i;

    for (v = 0; v < sizeof vectors / sizeof vectors[0]; v++) {
        check(fn(out, vectors[v].k, vectors[v].u) == 0 && memcmp(out, vectors[v].expected, 32) == 0, name);
    }

    /* RFC 7748 section 5.2 iterated vector: k = X25519(k, u), u = old k */
    memcpy(k, x25519_basepoint, 32);
    memcpy(u, x25519_basepoint, 32);
    for (i = 0; i < 1000; i++) {
        if (fn(out, k, u) != 0) {
            check(0, name);
            return;
        }
        memcpy(u, k, 32);
        memcpy(k, out, 32);
        if (i == 0) {
            check(memcmp(k, x25519_iter1, 32) == 0, name);
        }
    }
    check(memcmp(k, x25519_iter1000, 32) == 0, name);
}

static void test_x25519_differential(void)
{
    unsigned char k[32], u[32], a[32], b[32];
    int i;

    for (i = 0; i < 500; i++) {
        randombytes_buf(k, 32);
        randombytes_buf(u, 32);
#ifndef SODIUM_ESPHOME_X25519_M15
        /* the library's X25519 is ref10 here; in the ESP8266 build it is the
           ladder itself, so the base point check below carries that build */
        check(sodium_esphome_x25519_m15(a, k, u) == 0 && crypto_scalarmult_curve25519(b, k, u) == 0 &&
                  memcmp(a, b, 32) == 0,
              "m15 ladder vs library X25519");
#endif
        /* the base point multiply goes through the Edwards tables, an
           independent implementation of the same function */
        check(sodium_esphome_x25519_m15(a, k, x25519_basepoint) == 0 &&
                  crypto_scalarmult_curve25519_base(b, k) == 0 && memcmp(a, b, 32) == 0,
              "m15 ladder vs library base point multiply");
    }
}

int main(void)
{
    /* FIPS 180-4 example: SHA-256("abc"). Guards the round constant table
       patch 07 relocates on ESP8266. */
    {
        static const unsigned char expected[32] = {
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
            0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
        };
        unsigned char out[32];
        crypto_hash_sha256(out, (const unsigned char *) "abc", 3);
        check(memcmp(out, expected, 32) == 0, "sha256 known answer");
    }

    test_rfc8439_kat();
    test_x25519_vectors(crypto_scalarmult_curve25519, "library X25519 RFC 7748 vectors");
    test_x25519_vectors(sodium_esphome_x25519_m15, "m15 ladder RFC 7748 vectors");
    test_x25519_differential();
#ifdef SODIUM_ESPHOME_NOISE_FAST_PATH
    test_session_differential();
    test_session_counter_continuation();
    printf("session fast path exercised\n");
#else
    printf("session fast path not present; reference tests only\n");
#endif
    if (failures) {
        printf("%d failure%s\n", failures, failures == 1 ? "" : "s");
        return 1;
    }
    printf("all known-answer and differential tests passed\n");
    return 0;
}
