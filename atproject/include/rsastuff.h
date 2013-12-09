/*
 * rsastuff.h
 *
 *  Created on: 05.10.2012
 *      Author: micha
 */

#ifndef RSASTUFF_H_
#define RSASTUFF_H_

#define MAX_LEN 256

int pass_cb( char *buf, int size, int rwflag, void *u );
RSA* getRsaFp( const char* rsaprivKeyPath );
RSA* getRsaFp2( const char* rsapubKeyPath );
void setRsaKeys(char *rsaprivKeyPath,char *rsapubKeyPath,char *rsapubKeyPath2);
void unInit();
int signData(unsigned char *clearText, int clearlen,unsigned char *sig, int *sigLen );
int verifyData( char *clearText, int clearlen,unsigned char *sig, int sigLen);
int sha1(unsigned char *ibuf,unsigned char *obuf,int len);
int sign(unsigned char *hash,unsigned char *digest,RSA *r,unsigned int *len);
unsigned char *base64(const unsigned char *input, int length,int *b64len);
unsigned char *unbase64(unsigned char *input, int length);
int asev_log(char *text,RSA *priv);
void getLastHash(unsigned char *lasthash);

#endif /* RSASTUFF_H_ */
