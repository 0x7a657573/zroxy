/**********************************************************************
 * File : fifo.h
 * Copyright (c) Zeus@Sisoog.com.
 * Created On : Tue Apr 26 2022
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 **********************************************************************/

#ifndef HARDFIFO_H
#define HARDFIFO_H
#include <zroxy/fifo_port.h>

typedef struct
{
	char 	 *Buffer;
	uint16_t wr_index;
	uint16_t rd_index;
	uint16_t counter;
	uint16_t MessageSize;
	uint16_t MessageItem;
	fifo_mutex_t Mutex_Id;
	fifo_cond_t  NotEmpty;
	bool		 closed;
}fifo_t;



bool fifo_init(fifo_t *self,uint16_t MessageSize,uint16_t ItemNumber);
void fifo_deinit(fifo_t *self);
bool fifo_push(fifo_t *self,void *data);
bool fifo_pop(fifo_t *self,void *data);
/* Block until an item is available. Returns false once closed and drained. */
bool fifo_pop_wait(fifo_t *self,void *data);
/* Reject new items and wake every fifo_pop_wait caller. */
void fifo_close(fifo_t *self);
uint16_t fifo_count(fifo_t *self);

#endif /* HARDFIFO_H */
