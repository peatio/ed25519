#include <stdio.h>
#include <string.h>
#include "sha512.h"
#include "ed25519.h"

void print_charlist(unsigned char *list, int length){
    for(int i=0; i<length;i++) {
        printf("%d, ",list[i]);
    }
    puts("\n");
}
int test_sha512_hash() {

    unsigned char seed[32] = {118,232,213,67,126,97,12,170,23,115,35,172,202,113,73,254,73,155,243,18,101,70,17,24,150,118,243,223,10,57,246,6};
    SHA512_HASH digest;
    print_charlist(seed, 32);
    Sha512Calculate(seed, 32, &digest);
    for(int i=0; i<64; i++) {
        printf("%d ",digest.bytes[i]);
    }
    return 0;
}

int test_keypair() {

    return 0;
}

void combine_priv_and_public(unsigned char *priv, unsigned char *public, unsigned char *secret) {
    memcpy(secret, public, 32);
    memcpy(secret + 32, priv, 32);
}

int compare_signature_hex(unsigned char *signature, const char *expected_hex) {
    char signature_hex[129];
    for (int i = 0; i < 64; i++) {
        sprintf(signature_hex + i * 2, "%02x", signature[i]);
    }

    return strcmp(signature_hex, expected_hex) == 0;
}

int test_mixin_sign_and_verify() {
    unsigned char priv[32] = {201, 30, 9, 7, 209, 20, 253, 131, 193, 237, 195, 150, 73, 11, 178, 218, 250,
  67, 193, 152, 21, 176, 53, 78, 112, 220, 128, 195, 23, 195, 203, 10};
    unsigned char public[32];
    ed25519_public_key(public, priv);
    unsigned char secret[64];
    combine_priv_and_public(priv, public, secret);

    unsigned char message[32]={240, 209, 132, 102, 60, 174, 180, 126, 120, 164, 47, 114, 53, 37, 15, 160,
  214, 25, 98, 161, 73, 98, 77, 5, 114, 155, 30, 149, 55, 198, 69, 79};

    unsigned char signature[64];
    ed25519_sign_mixin(signature, message, 32, secret);
    if (compare_signature_hex(signature, "ca22e4ad608bad7638072e420ff5dd45eeb82c8e732e67580413066edf4cb8c0e2e6642f9e08b698a553a51e5719610b55d5afd1a9b9f3c69c6c60434dd55707")) {
        puts("[mixin] signature1: match");
    } else {
        puts("[mixin] signature1: not match");
    }

    if(ed25519_verify(signature, message, 32, public)) {
        puts("[mixin] message1 verify: pass");
    } else {
        puts("[mixin] message1 verify: not pass");
    }

    unsigned char message2[32]={84, 67, 110, 206, 2, 23, 148, 102, 122, 156, 130, 211, 140, 77, 151, 70, 189,
  71, 234, 107, 25, 215, 151, 26, 79, 192, 68, 230, 6, 27, 69, 138};
    unsigned char signature2[64];
    ed25519_sign_mixin(signature2, message2, 32, secret);
    if (compare_signature_hex(signature2, "ae7bde216edf1f6b00d1d87a584b8ec433913ee7028d075b3a11aec13aea86ed472bb45976100d9e679180d1a7afce352304347fefe6bd64b407097c6f887208")) {
        puts("[mixin] signature2: match");
    } else {
        puts("[mixin] signature2: not match");
    }
    if(ed25519_verify(signature2, message2, 32, public)) {
        puts("[mixin] message2 verify: pass");
    } else {
        puts("[mixin] message2 verify: not pass");
    }
    return 0;
}

int test_sign_and_verify() {
    unsigned char seed[32] = {114,185,233,83,24,8,249,111,109,189,187,81,200,247,45,254,211,130,123,236,
      124,110,55,77,43,66,74,58,25,253,230,184};
    unsigned char public[32];
    unsigned char secret[64];
    unsigned char message[12]={116,101,115,116,32,109,101,115,115,97,103,101};
    unsigned char signature[64];
    ed25519_create_keypair(public, secret, seed);
    ed25519_sign(signature, message, 12, secret);
    if(ed25519_verify(signature, message, 12, public)) {
        puts("pass");
    }else{
        puts("not pass");
    }
    return 0;
}

int main() {
    test_mixin_sign_and_verify();
    test_sign_and_verify();
    return 0;
}
