/*
 * rsastuff.c
 *
 *  Created on: 02.10.2012
 *      Author: micha
 */

/*  gcc ./openssl_sign.c -lssl */

#include <stdio.h>
#include <string.h>
#include <error.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>

#include "rsastuff.h"

//const int MAX_LEN = 256;
EVP_PKEY *sKey = 0;
EVP_PKEY *pKey = 0;
EVP_PKEY *pKey2 = 0;
RSA *priv = 0;
RSA *pub = 0;
RSA *pub2=0;
char __lastHash[20];

int pass_cb( char *buf, int size, int rwflag, void *u )
{
  int len;
  char tmp[1024];
  printf( "Enter pass phrase for '%s': ", (char*)u );
  scanf( "%s", tmp );
  len = strlen( tmp );

  if ( len <= 0 ) return 0;
  if ( len > size ) len = size;

  memset( buf, '\0', size );
  memcpy( buf, tmp, len );
  return len;
}

RSA* getRsaFp( const char* rsaprivKeyPath )
{
  FILE* fp;
  fp = fopen( rsaprivKeyPath, "r" );
  if ( fp == 0 ) {
    fprintf( stderr, "Couldn't open RSA priv key: '%s'. %s\n",
             rsaprivKeyPath, strerror(errno) );
    exit(1);
  }

  RSA *rsa = 0;
  rsa = RSA_new();
  rsa = PEM_read_RSAPrivateKey(fp, 0, pass_cb, (char*)rsaprivKeyPath);
  fclose( fp );
  return rsa;
}

RSA* getRsaFp2( const char* rsapubKeyPath )
{
  FILE* fp;
  fp = fopen( rsapubKeyPath, "r" );
  if ( fp == 0 ) {
    fprintf( stderr, "Couldn't open RSA pub key: '%s'. %s\n",
             rsapubKeyPath, strerror(errno) );
    exit(1);
  }

  RSA *rsa = 0;
  rsa = RSA_new();
  rsa = PEM_read_RSA_PUBKEY(fp, 0, pass_cb, (char*)rsapubKeyPath);
  fclose( fp );
  return rsa;
}

void setRsaKeys(char *rsaprivKeyPath,char *rsapubKeyPath,char *rsapubKeyPath2)
{
	 SSL_load_error_strings();

	 OpenSSL_add_all_algorithms();
	 OpenSSL_add_all_ciphers();
	 OpenSSL_add_all_digests();

	 sKey = EVP_PKEY_new();
	 pKey = EVP_PKEY_new();
	 pKey2 = EVP_PKEY_new();

	 priv = getRsaFp( rsaprivKeyPath );
	 pub = getRsaFp2( rsapubKeyPath );
	 pub2 = getRsaFp2( rsapubKeyPath2 );

	 EVP_PKEY_set1_RSA( sKey, priv );
	 EVP_PKEY_set1_RSA( pKey, pub );
	 EVP_PKEY_set1_RSA( pKey2, pub2 );

}

void unInit()
{
	RSA_free( priv );
	RSA_free( pub );
	RSA_free( pub2 );
	EVP_PKEY_free( sKey );
	EVP_PKEY_free( pKey );
	EVP_PKEY_free( pKey2 );
	ERR_free_strings();
}

int signData( unsigned char *clearText, int clearlen,unsigned char *sig, int *sigLen )
{
  int sign;
  EVP_MD_CTX* ctx = 0;

  ctx = EVP_MD_CTX_create();
  EVP_SignInit_ex( ctx, EVP_sha256(), 0 );
  EVP_SignUpdate( ctx, clearText, clearlen);
  memset(sig, 0, MAX_LEN);
  sign=EVP_SignFinal(ctx,sig,(unsigned int*)sigLen,sKey);
  EVP_MD_CTX_destroy( ctx );
  return sign;
}

int verifyData( char *clearText, int clearlen,unsigned char *sig, int sigLen)
{
  int verify;
  EVP_MD_CTX* ctx = 0;

  ctx = EVP_MD_CTX_create();
  EVP_VerifyInit_ex( ctx, EVP_sha256(), 0 );
  EVP_VerifyUpdate( ctx, clearText, clearlen );
  verify=EVP_VerifyFinal( ctx, sig, sigLen, pKey );
  EVP_MD_CTX_destroy( ctx );

  return verify;
}

int sha1(unsigned char *ibuf,unsigned char *obuf,int len)
{
    SHA1(ibuf, len,obuf);
    memcpy(__lastHash,obuf,20);

    return 0;
}

int sign(unsigned char *hash,unsigned char *digest,RSA *r,unsigned int *len)
{
	RSA_sign(NID_sha1,hash, 20,digest,len, r);

	return 0;
}

unsigned char *base64(const unsigned char *input, int length, int *b64len)
{
	BIO *bmem, *b64;
	BUF_MEM *bptr;


	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64,BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	unsigned char *buff = (unsigned char *)malloc(bptr->length);
	memcpy(buff, bptr->data, bptr->length-1);
	buff[bptr->length-1] = 0;

	*b64len=bptr->length;

	BIO_free_all(b64);

	return buff;
}

unsigned char *unbase64(unsigned char *input, int length)
{
	BIO *b64, *bmem;

	unsigned char *buffer = (unsigned char *)malloc(length);
	memset(buffer, 0, length);

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new_mem_buf(input, length);
	bmem = BIO_push(b64, bmem);

	BIO_read(bmem, buffer, length);

	BIO_free_all(bmem);

	return buffer;
}

int asev_log(char *text,RSA *priv)
{
	unsigned char hash[20];
	unsigned char lasthash[20];
	unsigned char dgst[20];
	unsigned char *newtext;
	int i,b64len;
	unsigned int len;
	char *b64hash,*b64line;

	printf("asev_log(%s)\n",text);
	getLastHash(lasthash);

	printf("lasthash=");
	for(i=0;i<20;i++)
	{
		printf("%02x",lasthash[i]);fflush(stdout);
	}
	puts("");

	newtext=(unsigned char*)malloc(strlen(text)+21);
	memcpy(newtext,lasthash,20);
	strcpy((char*)newtext+20,text);

	sha1((unsigned char*)newtext,hash,20+strlen(text));

	sign(hash,dgst,priv,&len);

	printf("hash=");
	for(i=0;i<20;i++)
	{
		printf("%02x",hash[i]);fflush(stdout);
	}
	puts("");

	printf("dgst=");
	for(i=0;i<20;i++)
	{
		printf("%02x",dgst[i]);fflush(stdout);
	}
	puts("");
	//printf("verify=%d\n",RSA_verify(NID_sha1,hash,20,dgst,len,pub));

	//printf("b64/signature=%s\n",base64(dgst,len,&b64len));



	free(newtext);
	return 0;
}

void getLastHash(unsigned char *hash)
{
	static int count=0;

	if(count==0)
		memcpy(hash,"01234567890123456789",20);
	else
		memcpy(hash,__lastHash,20);

	count++;
}
