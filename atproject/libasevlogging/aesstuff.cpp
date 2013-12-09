/*
 * aesstuff.c
 *
 *  Created on: 10.10.2012
 *      Author: micha
 */


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include "aesstuff.h"

//EVP_CIPHER_CTX en, de;

/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int aes_gen_key(unsigned char **key,unsigned char **iv)
{
  int i, nrounds = 5;
  //unsigned char key[32], iv[32];
  unsigned char salt[8];
  unsigned char key_data[32];

  *key=(unsigned char*)malloc(32);
  *iv=(unsigned char*)malloc(32);

  RAND_bytes(salt,8);
  RAND_bytes(key_data,32);
  /*
   * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   * nrounds is the number of times the we hash the material. More rounds are more secure but
   * slower.
   */
  i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, 32, nrounds, *key, *iv);
  if (i != 32) {
    printf("Key size is %d bits - should be 256 bits\n", i);
    return -1;
  }

//  printf("\naeskey=");fflush(stdout);
//  for(int i=0;i<32;i++)
//	  printf("%02x",(*key)[i]);
//  printf("\naesiv=");
//  for(int i=0;i<16;i++)
//  	  printf("%02x",(*iv)[i]);
//  printf("\n");
//  EVP_CIPHER_CTX_init(&en);
//  printf("EVP_EncryptInit_ex(&en)=%d\n",EVP_EncryptInit_ex(&en, EVP_aes_256_cbc(), NULL, key, iv));
//  EVP_CIPHER_CTX_init(&de);
//  printf("EVP_DecryptInit_ex(&de)=%d\n",EVP_DecryptInit_ex(&de, EVP_aes_256_cbc(), NULL, key, iv));

  return 0;
}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *aes_encrypt(EVP_CIPHER_CTX *ctx,unsigned char *plaintext, int *len)
{
  /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
  int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
  unsigned char *ciphertext = (unsigned char*)malloc(c_len);

  /* allows reusing of 'e' for multiple encryption cycles */
  EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, NULL);

  /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
  EVP_EncryptUpdate(ctx, ciphertext, &c_len, plaintext, *len);

  /* update ciphertext with the final remaining bytes */
  EVP_EncryptFinal_ex(ctx, ciphertext+c_len, &f_len);

  *len = c_len + f_len;
  return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *ctx,unsigned char *ciphertext, int *len)
{
  /* because we have padding ON, we must allocate an extra cipher block size of memory */
  int p_len = *len, f_len = 0, rc=0;
  unsigned char *plaintext = (unsigned char*)malloc(p_len + AES_BLOCK_SIZE);

  EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(ctx, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(ctx, plaintext+p_len, &f_len);

  *len = p_len + f_len;
  return plaintext;
}



