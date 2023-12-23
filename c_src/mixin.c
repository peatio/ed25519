#include "blake3.h"
#include "sc.h"
#include "ge.h"
#include <stdint.h>
#include <string.h>

#define SUCCESS 0
#define ERROR_INVALID_PUBLIC_KEY -1
#define ERROR_INVALID_PRIVATE_KEY -2

void mixin_hash_scalar(ge_p2 *point, uint64_t output_index, unsigned char* result) {
    unsigned char point_bytes[32];
    unsigned char index_bytes[8];
    unsigned char hash_input[40];
    unsigned char hash_output[64];

    // Convert point to bytes
    ge_tobytes(point_bytes, point);

    // Convert outputIndex to bytes in little-endian order
    for (int i = 0; i < 8; i++) {
        index_bytes[i] = (output_index >> (8 * i)) & 0xFF;
    }

    // Concatenate pointBytes and indexBytes
    memcpy(hash_input, point_bytes, 32);
    memcpy(hash_input + 32, index_bytes, 8);

    // Hash the input

  blake3_hasher hasher;
  blake3_hasher_init(&hasher);

  // Finalize the hash. BLAKE3_OUT_LEN is the default output length, 32 bytes.
  uint8_t output[BLAKE3_OUT_LEN];
  blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);

    // // Reduce the hash output modulo the group order to get a scalar
    // sc_reduce(hashOutput);

    // Copy the result
    // memcpy(result, hashOutput, 32);
}

typedef unsigned char mixin_key[32];

void test_blake3() {
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);

  // Finalize the hash. BLAKE3_OUT_LEN is the default output length, 32 bytes.
  uint8_t output[BLAKE3_OUT_LEN];
  blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);
}

int mixin_key_mult_pub_priv(const mixin_key* pub, const mixin_key* priv, ge_p2* result) {
    ge_p3 pub_point;
    unsigned char priv_scalar[32];
    unsigned char zero[32] = {0};

    // Convert public key to point
    if (ge_frombytes_negate_vartime(&pub_point, *pub) != 0) {
        return ERROR_INVALID_PUBLIC_KEY;
    }

    // Convert private key to scalar
    memcpy(priv_scalar, *priv, 32);
    sc_reduce(priv_scalar);

    // Check if the scalar is valid
    for (int i = 0; i < 32; i++) {
        if (priv_scalar[i] != 0) {
            break;
        }
        if (i == 31) {
            return ERROR_INVALID_PRIVATE_KEY;
        }
    }

    // Perform scalar multiplication
    ge_double_scalarmult_vartime(result, priv_scalar, &pub_point, zero);

    return SUCCESS;
}