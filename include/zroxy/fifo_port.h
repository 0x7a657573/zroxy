/**********************************************************************
 * File : fifo_port.h
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

#ifndef FIFO_PORT_H
#define FIFO_PORT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <pthread.h>

#define  fifo_memcpy                            memcpy
#define  fifo_memset                            memset

#define  fifo_malloc(size)		                malloc(size)
#define  fifo_free(ptr)		                    free(ptr)

typedef pthread_mutex_t fifo_mutex_t;
#define fifo_mutex_init(x)                     pthread_mutex_init(&x, NULL)
#define fifo_lock(x)                            pthread_mutex_lock(&x)
#define fifo_unlock(x)                          pthread_mutex_unlock(&x)    

typedef pthread_cond_t fifo_cond_t;
#define fifo_cond_init(x)                      pthread_cond_init(&x, NULL)
#define fifo_cond_destroy(x)                     pthread_cond_destroy(&x)
#define fifo_wait(c, m)                         pthread_cond_wait(&c, &m)
#define fifo_signal(c)                          pthread_cond_signal(&c)
#define fifo_broadcast(c)                       pthread_cond_broadcast(&c)

#endif /* FIFO_PORT_H */
