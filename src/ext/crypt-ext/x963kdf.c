/* X963kdf.h -- X9.63 Key Derivation Function
2023-03-22 : Stephane G. : Public domain */

#include "x963kdf.h"
// STEPHANE
#include<stdio.h>
#include <inttypes.h>

// function X963KDF(sharedSecret, sharedInfo, keySize){
//   var maxCount = Math.ceil(keySize/digestLen);
//   var result = Buffer.allocUnsafe(0);
//   for (var count = 1; count < maxCount + 1; count++){
//       var counter = Buffer.allocUnsafe(4);
//       counter.writeUInt32BE(count, 0);
//       var current = Buffer.concat([sharedSecret, counter, sharedInfo]);
//       var hash = crypto.createHash(digest).update(current).digest();
//       result = Buffer.concat([result, hash]);
//   }
  
//   return result.slice(0, keySize);
// }

void x963kdf(unsigned char *output, const unsigned char *sharedSecret, const unsigned char *sharedInfo, size_t keySize) 
{
    // int maxCount = ceil(keySize/SHA256_DIGEST_SIZE);
    int outlen = 0;
    int count = 1;

    size_t res_size;
    if (keySize%32 != 0){
        res_size = keySize + (32 - (keySize%32)); //eg: keySize = 74, 3 hashes -> 96, 74 + (32 - 10) = 74 + 22 = 96.
    }
    else{
        res_size = keySize;
    }

    uint8_t result[res_size];
    uint8_t counterBuf[4]; //1, 1 byte each -> total: 4 bytes : 32 bits.

    // printf("Size: %d",sizeof(counterBuf)); 


     while (keySize > outlen)
    {
        sha256_t ss;
        uint8_t hash[SHA256_DIGEST_SIZE];
        
        sha256_init(&ss);
        sha256_update(&ss, sharedSecret, 32);
        // To be improved in order to deal with Little and Big Endian
        counterBuf[0] = (uint8_t) ((count >> 24) & 0xff);
        counterBuf[1] = (uint8_t) ((count >> 16) & 0xff);
        counterBuf[2] = (uint8_t) ((count >> 8) & 0xff);
        counterBuf[3] = (uint8_t) ((count >> 0) & 0xff);

        sha256_update(&ss, counterBuf, 4);
        sha256_update(&ss, sharedInfo, 800); //800 key len
        sha256_final(&ss, hash);
        memcpy(result + (count-1)*SHA256_DIGEST_SIZE, hash, SHA256_DIGEST_SIZE);

        outlen += SHA256_DIGEST_SIZE;
        count += 1;
    }    
    memcpy(output, result, keySize);
}

// void x963kdf(uint8_t *output, const unsigned char *sharedSecret, const unsigned char *sharedInfo, size_t keySize,size_t sharedInfoSize){

//     size_t outlen = 0;
//     uint32_t counterBuf = 0x00000001; //1 hex -> 4 bits, 8 hex -> 32 bits
//     printf("\nsize 1: %d\n",sizeof(counterBuf));

//     uint8_t result[keySize];

//     int counter = 1;

//     while (keySize > outlen){

//         //first create a new hash object, to that add the (sharedSecret + counterBuf (in Big Endian format) +  the sharedInfo) in the same order, and calculate the hash, append this to the KDF, do this until the KDF length is achieved.
//         sha256_t ss;

//         uint8_t hash[SHA256_DIGEST_SIZE]; // 32 bytes (1,1 each  )

//         sha256_init(&ss);
//         sha256_update(&ss,sharedSecret,32);

//         uint32_t counterBuf2 = __builtin_bswap32(counterBuf);
//         printf("\nsize 2: %ld\n",sizeof(counterBuf2));
//         printf("\n Counter Buf: %x \n",counterBuf2);

//         uint8_t byte0, byte1, byte2, byte3;

//         // Extract each byte
//         byte0 = (counterBuf2 >> 24) & 0xFF;  // Extracts the first byte (most significant byte)
//         byte1 = (counterBuf2 >> 16) & 0xFF;  // Extracts the second byte
//         byte2 = (counterBuf2 >> 8) & 0xFF;   // Extracts the third byte
//         byte3 = counterBuf2 & 0xFF;          // Extracts the fourth byte (least significant byte)

//         printf("\nhere!\n");

//         sha256_update(&ss,&byte0,1);
//         sha256_update(&ss,&byte1,1);
//         sha256_update(&ss,&byte2,1);
//         sha256_update(&ss,&byte3,1);


//         sha256_update(&ss,sharedInfo,sharedInfoSize);
//         printf("\nerror\n");

//         sha256_final(&ss, hash);


//         memcpy(result + (counter -1)*SHA256_DIGEST_SIZE, hash, SHA256_DIGEST_SIZE);

//         outlen += sizeof(hash);
//         counterBuf++;

//     }

//     memcpy(output, result, keySize);

// }