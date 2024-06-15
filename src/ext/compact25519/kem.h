#ifndef KEM_H
#define KEM_H

#include "c25519/sha512.h"
#include <oqs/oqs.h>


#ifdef __cplusplus

#define KYBER_SHARED_SIZE 32
#define KYBER512 1

#ifdef KYBER512

    #define KYBER_PRIVATE_SIZE 1632
    #define KYBER_PUBLIC_SIZE 800
    #define KYBER_CIPHER_SIZE 768

#endif

extern "C"{
#endif

void cleanup_stack(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len);

void cleanup_heap(uint8_t* arr,size_t len);

void cleanup_heap2(uint8_t * arr);

static uint8_t* append(uint8_t *dst, const void * source, size_t length);

OQS_STATUS keypair_gen(uint8_t *privateKey, uint8_t *publicKey);

extern void key_encaps(const uint8_t *publicKey,uint8_t *sharedSecret, uint8_t *cipherText);

void derive_encryption_key(uint8_t *encryption_key,size_t key_size,const uint8_t* shared_secret,uint8_t * public_key);

#ifdef __cplusplus
}
#endif
#endif
