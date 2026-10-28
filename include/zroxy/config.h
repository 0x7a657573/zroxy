/*
 * config.h
 *
 *  Created on: Jun 2, 2021
 *      Author: zeus
 */

#ifndef CONFIG_H_
#define CONFIG_H_

/*max len of hostname*/
#define ZROXY_MAX_HOSTNAME		(255)

/*max ip len*/
#define ZROXY_MAX_IP_TEXT		(16)

/* DNS endpoint host, not including the NUL. */
#define ZROXY_MAX_DNS_HOST		(253)

/*max port len*/
#define ZROXY_MAX_PORT_TEXT	(10)

/* config line and value limits, including room for a NUL in the value buffer */
#define ZROXY_MAX_CONFIG_LINE		(1024)
#define ZROXY_MAX_CONFIG_VALUE	(512)

#endif /* CONFIG_H_ */
