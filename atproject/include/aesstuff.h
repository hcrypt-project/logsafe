/*
 * aesstuff.h
 *
 *  Created on: 10.10.2012
 *      Author: micha
 */

#ifndef AESSTUFF_H_
#define AESSTUFF_H_

#define AES_BLOCK_SIZE 16
//int aesmain(unsigned char *key_data);

int aes_gen_key(unsigned char **key,unsigned char **iv);
unsigned char *aes_encrypt(EVP_CIPHER_CTX *ctx,unsigned char *plaintext, int *len);
unsigned char *aes_decrypt(EVP_CIPHER_CTX *ctx,unsigned char *ciphertext, int *len);
//void aes_easy_encrypt();

#endif /* AESSTUFF_H_ */
