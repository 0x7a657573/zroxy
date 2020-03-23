/*
 * args.c
 *
 *  Created on: Feb 16, 2020
 *      Author: zeus
 */
#include "args.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "version.h"
#include <stdbool.h>
#include <argp.h>

const char *argp_program_version = "zroxy "version ;
static char doc[] = "simple and smart sni-proxy.";
static error_t parse_opt(int key, char *arg, struct argp_state *state);
void Parse_Ports(zroxy_t *ptr,char *str);
void Parse_Socks(zroxy_t *ptr,char *str);
void Parse_Monit(zroxy_t *ptr,char *str);
void Parse_whitelist(zroxy_t *ptr,char *str);

static struct argp_option options[] =
{
    { "port", 'p', "port list", 0, "list of port to listen. -p 80,443,8080..."},
	{ "socks", 's', "socks proxy", 0, "set proxy for up stream. -s 127.0.0.1:9050"},
	{ "monitor", 'm', "monitor port", 0, "set monitor port. -m 1234"},
	{ "white", 'w' , "white list" , 0, "white list for host -w /etc/withlist.txt"},
    { 0 }
};

static struct argp argp = { options, parse_opt, NULL, doc, 0, 0, 0 };

bool arg_Init(zroxy_t *pgp,int argc, const char **argv)
{

	pgp->ports = NULL;
    argp_parse(&argp, argc, argv, 0, 0, pgp);
    return true;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	zroxy_t *setting = state->input;
    switch (key)
    {
		case 'p': Parse_Ports(setting,arg); break;
		case 's': Parse_Socks(setting,arg); break;
		case 'm': Parse_Monit(setting,arg); break;
		case 'w': Parse_whitelist(setting,arg); break;
		case ARGP_KEY_ARG: return 0;
		default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

void Parse_whitelist(zroxy_t *ptr,char *str)
{
	while(*str==' ') str++; /*remove space before path*/
	ptr->WhitePath = (char *)malloc(strlen(str)+1);
	bzero(ptr->WhitePath,strlen(str)+1);
	strcpy(ptr->WhitePath,str);
}

void Parse_Monit(zroxy_t *ptr,char *str)
{
	ptr->monitorPort = (uint16_t*)malloc(sizeof(uint16_t));
	*ptr->monitorPort = atol(str);
}

void Parse_Socks(zroxy_t *ptr,char *str)
{
	ptr->socks = (sockshost_t*)malloc(sizeof(sockshost_t));
	ptr->socks->port = 9050;
	memset(ptr->socks->host,0,_MaxHostName_);

	char *endname = strchr(str,':');
	if(endname)
	{
		*endname++ = 0;
		strncpy(ptr->socks->host,str,_MaxHostName_-1);
		ptr->socks->port = atol(endname);
	}
	else
	{
		strncpy(ptr->socks->host,str,_MaxHostName_-1);
	}
}

void Parse_Ports(zroxy_t *ptr,char *str)
{
	void *perv = NULL;
	do{
		ptr->ports = (lport_t*)malloc(sizeof(lport_t));
		ptr->ports->port = atol(str);
		ptr->ports->next = perv;
		perv = ptr->ports;
		str = strchr(str,',');
		if(str) str++;
	}while( str!=NULL );
}

void Free_PortList(zroxy_t *ptr)
{
	lport_t *p=ptr->ports;
	while(p)
	{
		lport_t *next = p->next;
		free(p);
		p=next;
	}
}
