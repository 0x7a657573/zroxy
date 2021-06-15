/*
 * version.h
 *
 *  Created on: Feb 15, 2020
 *      Author: zeus
 */

#ifndef VERSION_H_
#define VERSION_H_

#define version	 "0.5"
/*
 * Socks : Fix bug in detection domain/ip
 * SNI   : add remote port for send request to this port
 * SNI   : add local port for listen to this port
 * SNI   : add bind ip
 */

//#define version	 "0.4"
/*
 * Add DNS Proxy
 * Add Config File
 * Add u & d key for input argumant
 * DNS : Add dns proxy from Socks socket
 * Socks : add domain/ip support
 */

//#define version	 "0.3"
/*
 * monitor : show usage in human readable format
 * monitor : remove 'gmtime' function
 * monitor : close connection after replay
 * monitor : Apache Bench:'Requests per second:    17830.07 [#/sec]'
 * monitor : change form none block read to thread
 */

//#define version	 "0.2"
/*
 * Add Monitor and statistic
 * reject ip connection for sni client
 */

//#define version	 "0.1"
/*
 * Init Program version :)
 */


#endif /* VERSION_H_ */
