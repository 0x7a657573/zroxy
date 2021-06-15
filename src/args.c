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
#include <log/log.h>
#include <netdb.h>


static char doc[] = "zroxy v"version "\nsimple sni and dns proxy.";

static error_t parse_opt(int key, char *arg, struct argp_state *state);
void Parse_Ports(zroxy_t *ptr,char *str);
void Parse_Socks(zroxy_t *ptr,char *str);
void Parse_Monit(zroxy_t *ptr,char *str);
void Parse_whitelist(zroxy_t *ptr,char *str);
void Parse_DNSServer(zroxy_t *ptr,char *str);
void Parse_DnsUpstream(zroxy_t *ptr,char *str);

static struct argp_option options[] =
{
    { "port", 'p', "sni port", 0, "sni port that listens.\n<bind ip>:<local port>#<remote port>\n -p 127.0.0.1:8080#80,4433#433,853..."},
	{ "socks", 's', "socks proxy", 0, "set proxy for up stream. -s 127.0.0.1:9050"},
	{ "monitor", 'm', "monitor port", 0, "monitor port that listens. -m 1234"},
	{ "white", 'w' , "white list" , 0, "white list for host -w /etc/withlist.txt"},
	{ "dport", 'd' , "DNS local server" , 0, "dns server that listens. -d 0.0.0.0:53"},
	{ "dns", 'u' , "DNS servers to use" , 0, "upstream DNS providers. -u 8.8.8.8"},
    { 0 }
};

static struct argp argp = { options, parse_opt, NULL, doc, 0, 0, 0 };

bool arg_Init(zroxy_t *pgp,int argc, const char **argv)
{
	pgp->ports = NULL;
    argp_parse(&argp, argc, (char **)argv, 0, 0, pgp);
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
		case 'd': Parse_DNSServer(setting,arg); break;
		case 'u': Parse_DnsUpstream(setting,arg); break;
		case ARGP_KEY_ARG: return 0;
		default: return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

bool validate_number(char *str)
{
   while (*str)
   {
	   //if the character is not a number, return false
      if(!isdigit(*str))
      {
         return false;
      }
      str++; //point to next character
   }
   return true;
}

//check whether the IP is valid or not
bool validate_ip(char *ip)
{
   int i, num, dots = 0;
   char *ptr;
   if (ip == NULL)
      return false;

   //cut the string using dor delimiter
   ptr = strtok(ip, ".");
   if (ptr == NULL)
      return false;

   while (ptr)
   {
	   //check whether the sub string is holding only number or not
      if (!validate_number(ptr))
         return false;

         //convert substring to number
         num = atoi(ptr);
         if (num >= 0 && num <= 255)
         {
        	//cut the next part of the string
            ptr = strtok(NULL, ".");
            if (ptr != NULL)
               //increase the dot count
               dots++;
         } else
            return false;
    }

    //if the number of dots are not 3, return false
    if (dots != 3)
       return false;
      return true;
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

void Parse_DNSServer(zroxy_t *ptr,char *str)
{
	if(!ptr->dnsserver)
	{
		ptr->dnsserver = (dnshost_t*)malloc(sizeof(dnshost_t));
	}

	ptr->dnsserver->port = 53;
	bzero(ptr->dnsserver->host,_MaxIPAddress_);
	strcpy(ptr->dnsserver->host,"127.0.0.1");


	char *endname = strchr(str,':');
	if(endname)
	{
		*endname++ = 0;
		strncpy(ptr->dnsserver->host,str,_MaxIPAddress_-1);
		ptr->dnsserver->port = atol(endname);
	}
	else
	{
		strncpy(ptr->dnsserver->host,str,_MaxIPAddress_-1);
	}
}

void Parse_DnsUpstream(zroxy_t *ptr,char *str)
{
	/*check dns config is exisit*/
	if(!ptr->dnsserver)
	{
		ptr->dnsserver = (dnshost_t*)malloc(sizeof(dnshost_t));
		ptr->dnsserver->port = 53;
		bzero(ptr->dnsserver->host,_MaxIPAddress_);
		strcpy(ptr->dnsserver->host,"127.0.0.1");
	}

	char *port = "53";
	char *endname = strchr(str,':');
	if(endname)
	{
		*endname++ =0;
	}
	else
	{
		endname = port;
	}

	ptr->dnsserver->dnsserver.port = atol(endname);
	strcpy(ptr->dnsserver->dnsserver.ip,str);
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

		char *xptr = str;
		str = strchr(str,',');
		if(str)
		{
			*str++=0;
		}

		/*check for ip*/
		char *Iptr = strchr(xptr,':');
		if(Iptr)
		{
			*Iptr++=0;
			strcpy(ptr->ports->bindip,xptr);
			bool valid_ip = validate_ip(xptr);
			if(valid_ip==false)
			{
				log_error("[!] Error Not valid ip -> %s.",ptr->ports->bindip);
				exit(0);
			}

			xptr = Iptr;
		}
		else
		{
			strcpy(ptr->ports->bindip,"0.0.0.0");
		}

		char *Pptr = strchr(xptr,'#');
		if(Pptr)
		{
			*Pptr++=0;
			ptr->ports->local_port = atol(xptr);
			ptr->ports->remote_port = atol(Pptr);
		}
		else
		{
			ptr->ports->local_port = atol(xptr);
			ptr->ports->remote_port = ptr->ports->local_port;
		}

		ptr->ports->next = perv;
		perv = ptr->ports;

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
