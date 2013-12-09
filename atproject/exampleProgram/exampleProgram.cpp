/*
 ============================================================================
 Name        : exampleProgram.c
 Author      : Michael Brenner
 Version     :
 Copyright   : 
 Description : Uses shared library to print greeting
               To run the resulting executable the LD_LIBRARY_PATH must be
               set to ${project_loc}/libasevlogging/.libs
               Alternatively, libtool creates a wrapper shell script in the
               build directory of this program which can be used to run it.
               Here the script will be called exampleProgram.
 ============================================================================
 */

#include <stdio.h>
#include <asevlog.h>

int main()
{
	struct asevlog_ctx logctx;

	asevlog_init(&logctx,(char*)"/home/micha/alice_id_rsa",(char*)"/home/micha/bob_id_rsa.pub",(char*)"/home/micha/charlie_id_rsa.pub");

	asevlog(&logctx,(unsigned char*)"hello",6);
	asevlog(&logctx,(unsigned char*)"hello2",7);
	asevlog(&logctx,(unsigned char*)"hello3",7);
	asevlog(&logctx,(unsigned char*)"hello4",7);
	asevlog(&logctx,(unsigned char*)"hello5",7);
	asevlog(&logctx,(unsigned char*)"hello6",7);
	asevlog(&logctx,(unsigned char*)"hello7",7);

	asevlog_cleanup();

	return 0;
}

