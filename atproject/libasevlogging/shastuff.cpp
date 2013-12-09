/*
 * shastuff.c
 *
 *  Created on: 01.11.2012
 *      Author: micha
 */
#include <stdlib.h>
#include <openssl/sha.h>

unsigned char *sha256(unsigned char *string,int len)
{
    SHA256_CTX sha256;
    unsigned char *hash;

    hash=(unsigned char*)malloc(SHA256_DIGEST_LENGTH);
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, len);
    SHA256_Final(hash, &sha256);
    return hash;
}
