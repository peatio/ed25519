#include "ge.h"

typedef unsigned char mixin_key[32];

void mixin_hash_scalar(ge_p2 *point, uint64_t outputIndex, unsigned char* result);

int mixin_key_mult_pub_priv(const mixin_key* pub, const mixin_key* priv, ge_p2* result);

void test_blake3();