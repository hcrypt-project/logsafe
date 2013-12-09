/*
 * amq_producer.h
 *
 *  Created on: 04.11.2012
 *      Author: micha
 */

#ifndef AMQ_PRODUCER_H_
#define AMQ_PRODUCER_H_

void initAmqLib();
int sendMessage(const unsigned char *brokerURI,const unsigned char *queue,const unsigned char *message);

#endif /* AMQ_PRODUCER_H_ */
