#include "ed25519.h"
#include "sha512.h"
#include "ge.h"
#include "sc.h"
#include <string.h>


int ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len,  const unsigned char *private_key) {
    Sha512Context hash;
    unsigned char hram[64];
    unsigned char reduce[64];
    SHA512_HASH digest;
    SHA512_HASH digest1;
    unsigned char expanded_secret_key[32];
    ge_p3 R;

    Sha512Initialise(&hash);
    Sha512Update(&hash, private_key, 32);
    Sha512Finalise(&hash,&digest1);
    for(int i=0; i<32 ; i++) {
        expanded_secret_key[i] = digest1.bytes[i];
    }
    //memmove(expanded_secret_key, &digest1.bytes, 32); 
    expanded_secret_key[0] &= 248;
    expanded_secret_key[31] &= 63;
    expanded_secret_key[31] |= 64;

    Sha512Initialise(&hash);
    Sha512Update(&hash, digest1.bytes + 32, 32);
    Sha512Update(&hash, message, message_len);
    Sha512Finalise(&hash, &digest);
    for( int j=0; j<64; j++) {
        reduce[j] = digest.bytes[j];
    }
    sc_reduce(reduce);
    ge_scalarmult_base(&R, reduce);
    ge_p3_tobytes(signature, &R);

    Sha512Initialise(&hash);
    Sha512Update(&hash, signature, 32);
    Sha512Update(&hash, private_key+32, 32);
    Sha512Update(&hash, message, message_len);
    Sha512Finalise(&hash, (SHA512_HASH *)hram);

    sc_reduce(hram);
    sc_muladd(signature + 32, hram, expanded_secret_key, reduce);
    return 0;
}

int ed25519_sign_bytom(unsigned char *signature, const unsigned char *message, size_t message_len,  const unsigned char *private_key) {
    unsigned char psk[32];
    unsigned char ssk[32];
    for( int j=0; j<32; j++) {
        psk[j] = private_key[j];
    }
    for( int j=0; j<32; j++) {
        ssk[j] = private_key[j + 32];
    }

    SHA512_HASH messageDigest;
    SHA512_HASH hramDigest;

    Sha512Context hash;
    Sha512Initialise(&hash);
    Sha512Update(&hash, ssk, 32);
    Sha512Update(&hash, message, message_len);
    Sha512Finalise(&hash, &messageDigest);

    sc_reduce(messageDigest.bytes);
    unsigned char messageDigestReduced[32];
    for( int j=0; j<32; j++) {
        messageDigestReduced[j] = messageDigest.bytes[j];
    }

    ge_p3 R;
    ge_scalarmult_base(&R, messageDigestReduced);

    unsigned char encodedR[32];
    ge_p3_tobytes(encodedR, &R);

    unsigned char public_key[32];  //private_key to publicKey
    ed25519_public_key(public_key, (unsigned char *)private_key);
    Sha512Initialise(&hash);
    Sha512Update(&hash, encodedR, 32);
    Sha512Update(&hash, public_key, 32);
    Sha512Update(&hash, message, message_len);
    Sha512Finalise(&hash, &hramDigest);

    sc_reduce(hramDigest.bytes);
    unsigned char hramDigestReduced[32];
    for( int j=0; j<32; j++) {
        hramDigestReduced[j] = hramDigest.bytes[j];
    }

    unsigned char s[32];
    sc_muladd(s, hramDigestReduced, psk, messageDigestReduced);

    for( int j=0; j<32; j++) {
        signature[j] = encodedR[j];
    }
    for( int j=0; j<32; j++) {
        signature[j + 32] = s[j];
    }

    return 0;
}

int ed25519_sign_mixin(unsigned char *signature, const unsigned char *message, size_t message_len,  const unsigned char *secret) {
    Sha512Context hash;
    unsigned char digest1[64];
    unsigned char messageDigest[64];
    unsigned char hramDigest[64];
    SHA512_HASH digest;
    ge_p3 R;
    unsigned char z[32];
    unsigned char x[32];
    unsigned char y[32];
    unsigned char s[32];

    unsigned char *private_key = secret + 32;
    unsigned char *public_key = secret;

    // Compute digest1
    Sha512Initialise(&hash);
    Sha512Update(&hash, private_key, 32);
    Sha512Finalise(&hash, &digest);
    memmove(digest1, digest.bytes, 64);

    // Compute messageDigest
    Sha512Initialise(&hash);
    Sha512Update(&hash, digest1 + 32, 32);
    Sha512Update(&hash, message, 32); // Assuming message is 32 bytes
    Sha512Finalise(&hash, &digest);
    memmove(messageDigest, digest.bytes, 64);

    // Compute z
    sc_reduce(messageDigest);
    memmove(z, messageDigest, 32);

    // Compute R
    ge_scalarmult_base(&R, z);
    ge_p3_tobytes(signature, &R);

    // Compute hramDigest
    Sha512Initialise(&hash);
    Sha512Update(&hash, signature, 32);
    Sha512Update(&hash, public_key, 32); // Assuming public key is first half of secret
    Sha512Update(&hash, message, 32); // Assuming message is 32 bytes
    Sha512Finalise(&hash, &digest);
    memmove(hramDigest, digest.bytes, 64);

    // Compute x
    sc_reduce(hramDigest);
    memmove(x, hramDigest, 32);

    // Compute y
    memmove(y, private_key, 32);

    // Compute s
    sc_muladd(s, x, y, z);

    // Copy s into second half of signature
    memmove(signature + 32, s, 32);

    return 0;
}
