/* Copyright (c) 2016, David Hauweele <david@hauweele.net>
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this
       list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
   ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _STACK_H_
#define _STACK_H_

#include <stdint.h>
#include <stdlib.h>

struct gpushd_item {
  int len;
  char data[];
};

/* Push an item on the stack and return
    memory used (for this entry). */
size_t push(const void *data, size_t len);

/* Get the element at the top of the stack.
   This element should not be modified,
   but you can copy the data if needed. */
const struct gpushd_item * get(void);

/* Free the element at the top of the stack.  Note that this
   function does not return the element. If you want to
   access the element you should do a get() prior to pop().
   This function returns the amount of memory freed. */
size_t pop(void);

/* Reset the stack. */
void clean(void);

/* Visit each element of the stack. */
int walk(int (*visit)(const struct gpushd_item *, void *), void *data);

/* Return non zero if the stack is empty.
   Return zero if the stack is not empty. */
int is_empty(void);

/* Get the real quantity of memory used
   including pre-allocation. */
uint64_t get_real_mem(void);

#endif /* _STACK_H_ */
