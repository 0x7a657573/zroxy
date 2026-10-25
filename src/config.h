/*
 * config.h
 *
 *  Created on: Jun 2, 2021
 *      Author: zeus
 */

#ifndef CONFIG_H_
#define CONFIG_H_

/*max len of hostname*/
#define _MaxHostName_		(255)

/*max ip len*/
#define _MaxIPAddress_		(16)

/* DNS endpoint host, not including the NUL. */
#define _MaxDNSHost_		(253)

/*max port len*/
#define _MaxPORTAddress_	(10)

/* config line and value limits, including room for a NUL in the value buffer */
#define _MaxConfigLine_		(1024)
#define _MaxConfigValue_	(512)

/*max dns queue size*/
#define _MaxDNSQUEUE_		(128)
#endif /* CONFIG_H_ */
