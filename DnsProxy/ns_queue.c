/*
 * ns_queue.c
 *
 *  Created on: Jun 3, 2021
 *      Author: zeus
 */
#include <ns_queue.h>
#include <stdlib.h>


ns_queue_t *ns_qeueu_init(int max_queue)
{
	ns_queue_t *ptr = malloc(sizeof(ns_queue_t));
	if(!ptr)
		return NULL;

	ptr->id_addr_queue = malloc(sizeof(id_addr_t)*max_queue);
	if(!ptr->id_addr_queue)
	{
		free(ptr);
		return NULL;
	}

	ptr->max_addr_queue = max_queue;
	ptr->id_addr_queue_pos = 0;
	return ptr;
}

void ns_queue_add(ns_queue_t *queue,id_addr_t id_addr)
{
  queue->id_addr_queue_pos = (queue->id_addr_queue_pos + 1) % queue->max_addr_queue;

  // free next hole
  id_addr_t old_id_addr = queue->id_addr_queue[queue->id_addr_queue_pos];
  free(old_id_addr.addr);

  queue->id_addr_queue[queue->id_addr_queue_pos] = id_addr;
}

id_addr_t *ns_queue_lookup(ns_queue_t *queue,uint16_t id)
{
  for (int i = 0; i < queue->max_addr_queue; i++)
  {
    if (queue->id_addr_queue[i].id == id)
      return queue->id_addr_queue + i;
  }
  return NULL;
}
