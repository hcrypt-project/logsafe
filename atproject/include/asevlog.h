/*
 * asevlog.h
 *
 *  Created on: 14.11.2012
 *      Author: micha
 */

#ifndef ASEVLOG_H_
#define ASEVLOG_H_

#include <openssl/sha.h>
struct asevlog_ctx
{
	unsigned char hash[SHA256_DIGEST_LENGTH];
};

int asevlog(struct asevlog_ctx *ctx,unsigned char *message,int mlen);
int asevlog_init(struct asevlog_ctx *ctx,char *rsaprivKeyPath,char *rsapubKeyPath,char *rsapubKeyPath2);
int asevlog_cleanup();

#endif /* ASEVLOG_H_ */
