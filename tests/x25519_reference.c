/* Upstream's ref10 X25519 base point multiply, as it is at the pinned tag, for
   the differential in kat.c. run_kat.sh builds this against a pristine copy
   of the submodule; every symbol is renamed so the copies link beside the
   fork's. */
#define crypto_scalarmult_curve25519_ref10 ref_crypto_scalarmult_curve25519_ref10
#define crypto_scalarmult_curve25519_ref10_base ref_crypto_scalarmult_curve25519_ref10_base
#define crypto_scalarmult_curve25519_ref10_implementation ref_crypto_scalarmult_curve25519_ref10_implementation
#define fe25519_frombytes ref_fe25519_frombytes
#define fe25519_invert ref_fe25519_invert
#define fe25519_tobytes ref_fe25519_tobytes
#define ge25519_add ref_ge25519_add
#define ge25519_double_scalarmult_vartime ref_ge25519_double_scalarmult_vartime
#define ge25519_from_hash ref_ge25519_from_hash
#define ge25519_from_uniform ref_ge25519_from_uniform
#define ge25519_frombytes ref_ge25519_frombytes
#define ge25519_frombytes_negate_vartime ref_ge25519_frombytes_negate_vartime
#define ge25519_has_small_order ref_ge25519_has_small_order
#define ge25519_is_canonical ref_ge25519_is_canonical
#define ge25519_is_on_curve ref_ge25519_is_on_curve
#define ge25519_is_on_main_subgroup ref_ge25519_is_on_main_subgroup
#define ge25519_p1p1_to_p2 ref_ge25519_p1p1_to_p2
#define ge25519_p1p1_to_p3 ref_ge25519_p1p1_to_p3
#define ge25519_p3_to_cached ref_ge25519_p3_to_cached
#define ge25519_p3_tobytes ref_ge25519_p3_tobytes
#define ge25519_scalarmult ref_ge25519_scalarmult
#define ge25519_scalarmult_base ref_ge25519_scalarmult_base
#define ge25519_sub ref_ge25519_sub
#define ge25519_tobytes ref_ge25519_tobytes
#define ristretto255_from_hash ref_ristretto255_from_hash
#define ristretto255_frombytes ref_ristretto255_frombytes
#define ristretto255_p3_tobytes ref_ristretto255_p3_tobytes
#define sc25519_invert ref_sc25519_invert
#define sc25519_is_canonical ref_sc25519_is_canonical
#define sc25519_mul ref_sc25519_mul
#define sc25519_muladd ref_sc25519_muladd
#define sc25519_reduce ref_sc25519_reduce

/* a helper upstream only reaches from code this build does not enable */
#pragma GCC diagnostic ignored "-Wunused-function"
#include "crypto_core/ed25519/ref10/ed25519_ref10.c"
#include "crypto_scalarmult/curve25519/ref10/x25519_ref10.c"

int
ref_x25519_base(unsigned char *q, const unsigned char *n)
{
    return crypto_scalarmult_curve25519_ref10_base(q, n);
}
