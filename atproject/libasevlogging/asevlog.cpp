/*
 * main.c
 *
 *  Created on: 08.06.2012
 *      Author: micha
 */
/*
RSA *PEM_read_RSAPrivateKey(FILE *fp, RSA **x,
                                    pem_password_cb *cb, void *u);

RSA *PEM_read_RSAPublicKey(FILE *fp, RSA **x,
                                    pem_password_cb *cb, void *u);
 *
 */

//	RSA *priv;
//	RSA *pub;
//	FILE *fp;
//
//	fp=fopen("/home/micha/alice_id_rsa","r");
//	priv=PEM_read_RSAPrivateKey(fp,NULL,NULL, NULL);
//	fclose(fp);
//
//	fp=fopen("/home/micha/alice_id_rsa.pub","r");
//	pub=PEM_read_RSA_PUBKEY(fp,NULL,NULL, NULL);
//	fclose(fp);
//
//	printf("priv=%08x\n",(unsigned int)priv);
//	printf("pub =%08x\n",(unsigned int)pub);
//
//	asev_log("hier ist der log-text1",priv);
//
//	asev_log("hier ist der log-text2",priv);
//
//	RSA_free(priv);
//	RSA_free(pub);

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/objects.h>
#include <openssl/rand.h>

#include "rsastuff.h"
#include "aesstuff.h"
#include "shastuff.h"
#include "asevlog.h"
#include <amq_producer.h>

void hexdump(char *title,unsigned char *buffer, int len,FILE *out);

void hexdump(char *title,unsigned char *buffer, int len,FILE *out)
{
	if(title!=NULL)
		fprintf(out,"%s\n",title);

	for(int i=0;i<len;i++)
	{
		if(i>0&&i%16==0)
			fprintf(out,"\n");
		fprintf(out,"%02x",buffer[i]);
	}
	fprintf(out,"\n");
}
int asevlog_init(struct asevlog_ctx *ctx,char *rsaprivKeyPath,char *rsapubKeyPath,char *rsapubKeyPath2)
{
	FILE *f;

	initAmqLib();
	setRsaKeys(rsaprivKeyPath,rsapubKeyPath,rsapubKeyPath2);

	if(f=fopen(".asevlog","rb"))
	{
		if(fread(ctx->hash,1,SHA256_DIGEST_LENGTH,f)==SHA256_DIGEST_LENGTH)
		{
			fclose(f);
			return 0;
		}
		fclose(f);
	}
	RAND_bytes(ctx->hash,SHA256_DIGEST_LENGTH);

	if(f=fopen(".asevlog","wb"))
	{
		if(fwrite(ctx->hash,1,SHA256_DIGEST_LENGTH,f)==SHA256_DIGEST_LENGTH)
		{
			fclose(f);
			return 0;
		}
		fprintf(stderr,"can't write .asevlog\n");
	}

	exit(1);
}

int asevlog_cleanup()
{
	unInit();
}

int asevlog(struct asevlog_ctx *ctx,unsigned char *message,int mlen)
{
	FILE *f;
	unsigned char *plain_buffer,*cipher_buffer;
	unsigned char *hasht,*rsa_enc_buffer,*rsa_result,*rsa_result2;
	int plain_buffer_len=0,cipher_buffer_len=0,rsa_len=0,pub_2=0;
	unsigned char *aes_key,*aes_iv;
	EVP_CIPHER_CTX aes_enc_ctx;
	time_t timestamp;
	unsigned char *usersig;
	int usersiglen;
	extern RSA *pub,*pub2,*priv;
	extern EVP_PKEY *sKey;
	char *messagebuffer=0;
	char hashcmp[SHA256_DIGEST_LENGTH];
	time(&timestamp);

	//printf("timestamp=%d\n",timestamp);

	if(f=fopen(".asevlog","rb"))
	{
		if(fread(hashcmp,1,SHA256_DIGEST_LENGTH,f)==SHA256_DIGEST_LENGTH)
		{
			fclose(f);
			if(memcmp(hashcmp,ctx->hash,SHA256_DIGEST_LENGTH))
			{
				fprintf(stderr,".asevlog inconsistency\n");
				hexdump("stored hash",(unsigned char*)hashcmp,32,stderr);
				hexdump("previous hash",(unsigned char*)ctx->hash,32,stderr);
			}
		}
		else
		{
			fprintf(stderr,".asevlog inconsistency\n");
		}
	}
	else
	{
		fprintf(stderr,"can't open .asevlog for precheck\n");
		exit(1);
	}

	aes_gen_key(&aes_key,&aes_iv);
	EVP_CIPHER_CTX_init(&aes_enc_ctx);
	EVP_EncryptInit_ex(&aes_enc_ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);

//	hexdump("\naeskey",aes_key,32);

//	hexdump("hasht-1",ctx->hash,32);

	cipher_buffer_len=
	plain_buffer_len=mlen+sizeof(int)
			  	     +SHA256_DIGEST_LENGTH //hash t-1
					 +32 //aes key als nonce nur für den digest (wird dann abgeschnitten)
					 +sizeof(time_t) //timestamp
					 +SHA256_DIGEST_LENGTH; //hash t

	messagebuffer=(char*)malloc((2*plain_buffer_len)+10000+10000);

//	printf("plain len=%d\n",plain_buffer_len);

	plain_buffer=(unsigned char*)malloc(plain_buffer_len);

	memcpy(plain_buffer,ctx->hash,SHA256_DIGEST_LENGTH);
	//memcpy(plain_buffer+SHA256_DIGEST_LENGTH,aes_key,32);
	memcpy(plain_buffer+SHA256_DIGEST_LENGTH,&timestamp,sizeof(time_t));
	memcpy(plain_buffer+SHA256_DIGEST_LENGTH+sizeof(time_t),&mlen,sizeof(int));
	memcpy(plain_buffer+SHA256_DIGEST_LENGTH+sizeof(time_t)+sizeof(int),message,mlen);
	memcpy(plain_buffer+SHA256_DIGEST_LENGTH+sizeof(time_t)+sizeof(int)+mlen,aes_key,32);

	//printf("message offset=%d\n",SHA256_DIGEST_LENGTH+sizeof(time_t)+sizeof(int));

//	printf("\n");
	plain_buffer_len=SHA256_DIGEST_LENGTH+sizeof(time_t)+sizeof(int)+mlen; //aes-key abschneiden
	hasht=sha256(plain_buffer,plain_buffer_len+32);
//	hexdump("hash t",hasht,32);

//	hexdump("signed buffer:",plain_buffer,plain_buffer_len+32);

	unsigned char *b64;
	int b64len;
	//b64=base64(hasht,SHA256_DIGEST_LENGTH,&b64len);
	//printf("%s;",b64);
	//strcpy(messagebuffer,(char*)b64);strcat(messagebuffer,";");
	//free(b64);

	usersig=(unsigned char*)malloc(RSA_size(priv));
	//signData(hasht,SHA256_DIGEST_LENGTH,usersig,&usersiglen);
	signData(plain_buffer,plain_buffer_len+32,usersig,&usersiglen);
	//printf("\nsigned buffer len=%d\n",plain_buffer_len);

//	printf("usersiglen=%d\n",usersiglen);


	b64=base64(usersig,usersiglen,&b64len);
//	printf("%s;",b64);
	strcpy(messagebuffer,(char*)b64);strcat(messagebuffer,";");
	free(b64);
	free(usersig);

	memcpy(plain_buffer+SHA256_DIGEST_LENGTH+sizeof(time_t)+sizeof(int)+mlen,hasht,SHA256_DIGEST_LENGTH);

	cipher_buffer=aes_encrypt(&aes_enc_ctx,plain_buffer,&cipher_buffer_len);

//	printf("cipher len=%d\n",cipher_buffer_len);

	free(plain_buffer);

	rsa_enc_buffer=(unsigned char*)malloc(64);
	rsa_result=(unsigned char*)malloc(RSA_size(pub));
	rsa_result2=(unsigned char*)malloc(2*RSA_size(pub2));

	memcpy(rsa_enc_buffer,aes_key,32);
	memcpy(rsa_enc_buffer+32,aes_iv,32);

	pub_2=RSA_size(pub)/2;
//	printf("pub/2=%d\n",pub_2);

	rsa_len=RSA_public_encrypt(64,rsa_enc_buffer,rsa_result,pub,RSA_PKCS1_PADDING);
//	printf("rsa 1 len=%d\n",rsa_len);

	rsa_len=RSA_public_encrypt(pub_2,rsa_result,rsa_result2,pub2,RSA_PKCS1_PADDING);
//	printf("rsa 2a len=%d\n",rsa_len);

	rsa_len=RSA_public_encrypt(pub_2,rsa_result+pub_2,rsa_result2+RSA_size(pub),pub2,RSA_PKCS1_PADDING);
//	printf("rsa 2b len=%d\n",rsa_len);



	b64=base64(rsa_result2,2*RSA_size(pub),&b64len);
	strcat(messagebuffer,(char*)b64);strcat(messagebuffer,";");
	//printf("%s;",b64);
	free(b64);

	b64=base64(cipher_buffer,cipher_buffer_len,&b64len);
	strcat(messagebuffer,(char*)b64);strcat(messagebuffer,";");
	//printf("%s\n",b64);
	free(b64);

	sendMessage((unsigned char*)"tcp://127.0.0.1:61616?wireFormat=openwire",
				(unsigned char*)"queue.log.asev",
				(unsigned char*)messagebuffer);

	//printf("buffer:%s\n",messagebuffer);

//	EVP_CIPHER_CTX_cleanup(&aes_dec_ctx);
	EVP_CIPHER_CTX_cleanup(&aes_enc_ctx);
	free(rsa_enc_buffer);
	free(rsa_result);
	free(rsa_result2);
	free(cipher_buffer);
	free(messagebuffer);
	free(aes_iv);
	free(aes_key);
//
//	plain_buffer_len=cipher_buffer_len;
//	EVP_CIPHER_CTX_init(&aes_dec_ctx);
//	EVP_DecryptInit_ex(&aes_dec_ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv);
//	plain_buffer=aes_decrypt(&aes_dec_ctx,cipher_buffer,&plain_buffer_len);
//
//	printf("message=%s\n",plain_buffer+64+sizeof(time_t));
	memcpy(ctx->hash,hasht,SHA256_DIGEST_LENGTH);
	free(hasht);

	if(f=fopen(".asevlog","wb"))
	{
		if(fwrite(ctx->hash,1,SHA256_DIGEST_LENGTH,f)==SHA256_DIGEST_LENGTH)
		{
			fclose(f);
		}
		else
		{
			fprintf(stderr,"can't write .asevlog\n");

		}

	}
	else
		fprintf(stderr,"can't open .asevlog\n");

	return 0;
}
