/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// START SNIPPET: demo

#include <decaf/lang/Thread.h>
#include <decaf/lang/Runnable.h>
#include <decaf/util/concurrent/CountDownLatch.h>
#include <decaf/lang/Integer.h>
#include <decaf/util/Date.h>
#include <activemq/core/ActiveMQConnectionFactory.h>
#include <activemq/util/Config.h>
#include <activemq/library/ActiveMQCPP.h>
#include <cms/Connection.h>
#include <cms/Session.h>
#include <cms/TextMessage.h>
#include <cms/BytesMessage.h>
#include <cms/MapMessage.h>
#include <cms/ExceptionListener.h>
#include <cms/MessageListener.h>
#include <stdlib.h>
#include <iostream>
#include <memory>
#include <stdio.h>

#include "amq_producer.h"

using namespace activemq::core;
using namespace decaf::util::concurrent;
using namespace decaf::util;
using namespace decaf::lang;
using namespace cms;
using namespace std;

class HelloWorldProducer : public Runnable {
private:

    Connection* connection;
    Session* session;
    Destination* destination;
    MessageProducer* producer;
    int numMessages;
    bool useTopic;
    bool sessionTransacted;
    const unsigned char *brokerURI;
    const unsigned char *queue;
    const unsigned char *message;

public:

    HelloWorldProducer( const unsigned char *brokerURI,
    					const unsigned char *queue,
                        const unsigned char *message )
    {
        this->connection = NULL;
        this->session = NULL;
        this->destination = NULL;
        this->producer = NULL;
        this->useTopic = false;
        this->sessionTransacted = true;
        this->brokerURI = brokerURI;
        this->queue=queue;
        this->message=message;

//        cout<<"brokerURI="<<brokerURI<<"\n";
//        cout<<"queue="<<queue<<"\n";
    }

    virtual ~HelloWorldProducer()
    {
        cleanup();
    }

    virtual void run()
    {

        try {
            // Create a ConnectionFactory
            auto_ptr<ConnectionFactory> connectionFactory(
                ConnectionFactory::createCMSConnectionFactory( (const char*)brokerURI ) );

            // Create a Connection
            connection = connectionFactory->createConnection();
            connection->start();

            // Create a Session
            if( this->sessionTransacted ) {
                session = connection->createSession( Session::SESSION_TRANSACTED );
            } else {
                session = connection->createSession( Session::AUTO_ACKNOWLEDGE );
            }

            destination = session->createQueue((const char*)queue);
            //destination = session->createQueue("/asev/queue");
            // Create a MessageProducer from the Session to the Topic or Queue
            producer = session->createProducer( destination );
            producer->setDeliveryMode( DeliveryMode::PERSISTENT );

            //cout<<"message:"<<message<<"\n";

			TextMessage* sendmessage = session->createTextMessage( (char*)message );

			//cout<<"producer:"<<sendmessage->getText()<<"\n";
			// Tell the producer to send the message
			//printf( "Sent message #%d from thread %s\n", ix+1, threadIdStr.c_str() );
			producer->send( sendmessage );

			if(this->sessionTransacted)
				session->commit();

			delete sendmessage;


        }catch ( CMSException& e ) {
            e.printStackTrace();
        }
    }

private:

    void cleanup()
    {

        // Destroy resources.
        try{
            if( destination != NULL ) delete destination;
        }catch ( CMSException& e ) { e.printStackTrace(); }
        destination = NULL;

        try{
            if( producer != NULL ) delete producer;
        }catch ( CMSException& e ) { e.printStackTrace(); }
        producer = NULL;

        // Close open resources.
        try{
            if( session != NULL ) session->close();
            if( connection != NULL ) connection->close();
        }catch ( CMSException& e ) { e.printStackTrace(); }

        try{
            if( session != NULL ) delete session;
        }catch ( CMSException& e ) { e.printStackTrace(); }
        session = NULL;

        try{
            if( connection != NULL ) delete connection;
        }catch ( CMSException& e ) { e.printStackTrace(); }
        connection = NULL;
    }
};



void initAmqLib()
{
	activemq::library::ActiveMQCPP::initializeLibrary();
}

int sendMessage(const unsigned char *brokerURI,const unsigned char *queue,const unsigned char *message)
{
    HelloWorldProducer producer( brokerURI,queue,message );

    Thread producerThread( &producer );
    producerThread.start();

    producerThread.join();

    return 0;
}

// END SNIPPET: demo
