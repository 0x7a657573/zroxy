/*
 * SniClient.h
 *
 *  Created on: Jan 29, 2020
 *      Author: zeus
 */

#ifndef SNICLIENT_H_
#define SNICLIENT_H_
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <zroxy/sniproxy.h>

/* Single-connection path; compiled only into the SNI_TEST_HOOKS libraries. */
#ifdef SNI_TEST_HOOKS
typedef struct
{
	int		 connid;
	struct sockaddr_in cli;
	socklen_t addr_len;
	SniServer_t SniConfig;
}sniclient_t;


void *sni_client_handler(void *arg);
#endif /* SNI_TEST_HOOKS */


#endif /* SNICLIENT_H_ */
