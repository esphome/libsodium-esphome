/* Upstream's SHA256 compiled under other names, so that kat.c can check the
   patched library's SHA256 against it byte for byte. run_kat.sh extracts the
   file from the submodule at its pinned tag, before any patch, into the build
   dir. */
#define crypto_hash_sha256_init ref_sha256_init
#define crypto_hash_sha256_update ref_sha256_update
#define crypto_hash_sha256_final ref_sha256_final
#define crypto_hash_sha256 ref_sha256
#include "upstream_hash_sha256_cp.c"
