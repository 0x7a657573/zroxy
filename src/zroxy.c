/*
 ============================================================================
 Name        : Zroxy.c
 Author      : Zeus
 Version     :
 Copyright   : Copyright 2020 Mohammad Mazarei This program is free software
 Description : simple and smart sni-proxy.
 ============================================================================
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h> /*Lib Socket*/
#include <unistd.h>  	/*Header file for sleep(). man 3 sleep for details.*/
#include <pthread.h>
#include <log/log.h>
#include <sniproxy.h>
#include "version.h"
#include <netdb.h>		/* getaddrinfo, getnameinfo */ /*https://rosettacode.org/wiki/DNS_query#C*/

#include <argp.h>
#include <stdbool.h>
#include "args.h"
#include <monitor.h>
#include "filter/filter.h"

zroxy_t prg_setting = {0};


/*
 * for test dns server
 * dig @127.0.0.1 google.com -p5656
 *
 * about tcp/ip and socket in c:
 * https://www.csd.uoc.gr/~hy556/material/tutorials/cs556-3rd-tutorial.pdf
 *
 * for Non Block IO:
 * https://www.gnu.org/software/libc/manual/html_node/Waiting-for-I_002fO.html
 * https://www.gnu.org/software/libc/manual/html_node/Server-Example.html
 * https://www.tenouk.com/Module41.html
 * */
int main(int argc, const char **argv)
{

	Log_init();
	if(arg_Init(&prg_setting,argc,argv)==false)
	{
		log_error("use --help for more");
		return 1;
	}
	
	mon_t *monitor = NULL;
	/*check Monitor*/
	if(prg_setting.monitorPort)
	{
		log_info("enable monitor on port %i",*prg_setting.monitorPort);
		monitor = monitor_Init(prg_setting.monitorPort);
	}

	/*check for dns server*/
	if(prg_setting.dnsserver)
	{
		if(monitor)
			prg_setting.dnsserver->Stat = monitor_AddNewStat(monitor,"DNS Server");
		log_info("start dns server ...");
		dnsserver_init(prg_setting.dnsserver);
	}

	/*chack white list*/
	filter_t *whitelist = NULL;
	if(prg_setting.WhitePath)
	{
		log_info("load white list from %s",prg_setting.WhitePath);
		whitelist = filter_init(prg_setting.WhitePath);
		free(prg_setting.WhitePath);
	}

	lport_t *p=prg_setting.ports;
	statistics_t *SniStat = NULL;
	if(monitor)
		SniStat = monitor_AddNewStat(monitor,"SNI Server");

	SniServer_t Xconf = { /*.Port = {0},*/ .Socks = NULL ,.sta = SniStat ,.wlist = whitelist };
	/*if Set Socks proxy*/
	if(prg_setting.socks)
	{
		log_info("enable socks on %s:%i",prg_setting.socks->host,prg_setting.socks->port);
		Xconf.Socks = prg_setting.socks;
	}

	while(p)
	{
		Xconf.Port = *p;
		SniProxy_Start(&Xconf);

		p=p->next;
	}
	Free_PortList(&prg_setting); /*free Port List*/

	log_trace("exit from main thread");
	pthread_exit(NULL);		/* terminate the thread */
	//return 0;
}

