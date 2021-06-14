/*
 * ns_queue.h
 *
 *  Created on: Jun 3, 2021
 *      Author: zeus
 */

#ifndef NS_QUEUE_H_
#define NS_QUEUE_H_
#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>

typedef struct
{
  uint16_t id;
  uint16_t old_id;
  struct sockaddr *addr;
  socklen_t addrlen;
} id_addr_t;

typedef struct
{
	id_addr_t *id_addr_queue;
	int 	   id_addr_queue_pos;
	int 	   max_addr_queue;
}ns_queue_t;


ns_queue_t *ns_qeueu_init(int max_queue);
void queue_add(ns_queue_t *queue,id_addr_t id_addr);
id_addr_t *ns_queue_lookup(ns_queue_t *queue,uint16_t id);


#endif /* NS_QUEUE_H_ */
