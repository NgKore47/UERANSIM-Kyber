#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

#include "kem.h"



// Clean up the memory to remove any traces of the keys.
void cleanup_stack(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len) {
	OQS_MEM_cleanse(secret_key, secret_key_len);
	OQS_MEM_cleanse(shared_secret_e, shared_secret_len);
	OQS_MEM_cleanse(shared_secret_d, shared_secret_len);
}

//https://openquantumsafe.org/liboqs/api/common.html

/*void cleanup_heap(uint8_t *secret_key, uint8_t *shared_secret_e,
                  uint8_t *shared_secret_d, uint8_t *public_key,
                  uint8_t *ciphertext, OQS_KEM *kem) {
	if (kem != NULL) {
		OQS_MEM_secure_free(secret_key, kem->length_secret_key);
		OQS_MEM_secure_free(shared_secret_e, kem->length_shared_secret);
		OQS_MEM_secure_free(shared_secret_d, kem->length_shared_secret);
	}
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(ciphertext);
	OQS_KEM_free(kem);
}
*/
void cleanup_heap(uint8_t* arr,size_t len){

    /*this function is only for securely cleaning up the secret, shared secret in the heap & takes in a length param. For cleaning up the public key, & cipher_text use cleanup_heap2 */

    OQS_MEM_secure_free(arr,len);
}

void cleanup_heap2(uint8_t * arr){

    /*for cleaning up the public keys & cipher text.*/
    OQS_MEM_insecure_free(arr);

}

static uint8_t* append(uint8_t *dst, const void * source, size_t length) {
    memcpy(dst, source, length);
    return dst + length;
}


OQS_STATUS keypair_gen(uint8_t *privateKey, uint8_t *publicKey){

	//create a new OQS KEM 512

	OQS_KEM *kem = NULL;
kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
	if (kem == NULL) {
                printf("OQS_KEM_kyber_512 was not enabled at "
                       "compile-time.\n");
        exit(1);

	}

	printf("\nhello\n");
    size_t kem_length_pk = kem->length_public_key;
    size_t kem_length_sk = kem->length_secret_key;

    //these 2 will be cleaned at the end.
    uint8_t *public_key = NULL;
	uint8_t *private_key = NULL;

    public_key = malloc(kem_length_pk);
	private_key = malloc(kem_length_sk);

    //now check if the malloc happened correctly or not, cleanup everything incase not.
    if ((public_key == NULL) || (private_key == NULL)) {
		fprintf(stderr, "ERROR: malloc failed!\n");

        cleanup_heap(private_key,kem_length_sk);
        cleanup_heap2(public_key);

		return OQS_ERROR;
	}

    //generate the keypair
	OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, private_key);

	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_keypair failed!\n");
        
        cleanup_heap(private_key,kem_length_sk);
        cleanup_heap2(public_key);


		return OQS_ERROR;
	}

    //cleanup the heap, once copied
    memcpy(privateKey,private_key,kem_length_sk);
    memcpy(publicKey,public_key,kem_length_pk);

    
    cleanup_heap(private_key,kem_length_sk);
    cleanup_heap2(public_key);

}

void key_encaps(const uint8_t *publicKey,uint8_t *sharedSecret, uint8_t *cipherText){


	        OQS_KEM *kem = NULL;
kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
        if (kem == NULL) {
                printf("OQS_KEM_kyber_512 was not enabled at "
                       "compile-time.\n"); }

    uint8_t *cipher_text = NULL;
	uint8_t *shared_secret_e = NULL;

    size_t cipher_len = kem->length_ciphertext;
    size_t ss_len = kem->length_shared_secret;

    cipher_text = malloc(cipher_len);
	shared_secret_e = malloc(ss_len);

    if ((cipher_text == NULL) || (shared_secret_e == NULL)) {
		fprintf(stderr, "ERROR: malloc failed!\n");

        cleanup_heap(shared_secret_e,ss_len);
        cleanup_heap2(cipher_text);


		return OQS_ERROR;
	}

    OQS_STATUS rc = OQS_KEM_encaps(kem, cipher_text, shared_secret_e, publicKey);

	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_KEM_encaps failed!\n");
        cleanup_heap(shared_secret_e,ss_len);
        cleanup_heap2(cipher_text);


		return OQS_ERROR;
	}

    memcpy(cipherText, cipher_text,cipher_len);
    memcpy(sharedSecret,shared_secret_e,ss_len);

    cleanup_heap(shared_secret_e,ss_len);
    cleanup_heap2(cipher_text);

}

//derives an encryption key from the Shared secret concatenated with the public key, uses SHA512, use 32 bytes key_size fro AES256 encryption.

// void derive_encryption_key(uint8_t *encryption_key,size_t key_size,const uint8_t* shared_secret,uint8_t * public_key){

//     /*public key: Home Network's one, shared secret: one that we got from encapsulation. */

    
// 	        OQS_KEM *kem = NULL;
// kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
//         if (kem == NULL) {
//                 printf("OQS_KEM_kyber_512 was not enabled at "
//                        "compile-time.\n");
// 		exit(1);
// 	}	
// uint8_t key_data[32+800];
//     uint8_t *p = key_data;

//     p = append(p, shared_secret, kem->length_shared_secret);
//     p = append(p, public_key, kem->length_public_key);

//     struct sha512_state hasher;
//     sha512_init(&hasher); //create a new hash object

//     sha512_final(&hasher, key_data, sizeof(key_data));

//     //get the hash & fill in the buffer passed (here encryption key)
//     sha512_get(&hasher, encryption_key, 0, key_size);




// }
// int main(){


// 	size_t privateKeySize = 1632; // Assume size 32, adjust as per actual requirements
// size_t publicKeySize = 800;  // Same as above
// uint8_t *privateKey = malloc(privateKeySize);
// uint8_t *publicKey = malloc(publicKeySize);
// uint8_t *cipherText = malloc(768);
// uint8_t *sharedSecret = malloc(32);

// 	keypair_gen(privateKey,publicKey);
	
// 	printf("Secret Key: ");
// 	for(int i = 0;i<1632;i++){
		
// 		printf("%x",privateKey[i]);
	
// 	}
// 	printf("\n\n\n");

//         printf("Public Key: ");
//          for(int i = 0;i<800;i++){

//                  printf("%x",publicKey[i]);

//          }

// 	 key_encaps(publicKey, sharedSecret, cipherText);

// 	printf("\n\nCipher: ");
// 	for(int i = 0;i<768;i++){
		
// 		printf("%x",cipherText[i]);
	
// 	}
// 	printf("\n\nShared Secret: ");
// 	for(int i = 0;i<32;i++){
		
// 		printf("%x",sharedSecret[i]);
// 	}
// 	printf("\n");	


// 	free(privateKey);
// free(publicKey);
// free(cipherText);
// free(sharedSecret);
// }


// int main(){

//     printf("Hello world!");
//     return 0;
// }