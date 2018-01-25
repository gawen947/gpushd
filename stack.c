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

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include <gawen/safe-call.h>

#include "stack.h"
#include "gpushd-common.h"

/* items are placed on a simple FIFO stack
   implemented as a singly linked list. */
static struct stack_entry {
  struct stack_entry *next;

  struct gpushd_item item;
} *stack;

size_t push(const void *data, size_t len)
{
  /* amount of memory allocated */
  size_t size = sizeof(struct stack_entry) + len;

  /* create */
  struct stack_entry *entry = xmalloc(size);
  memcpy(entry->item.data, data, len);
  entry->item.len = len;

  /* push */
  entry->next = stack;
  stack      = entry;

  return size;
}

const struct gpushd_item * get(void)
{
  if(!stack)
    return NULL;
  return &stack->item;
}

size_t pop(void)
{
  size_t size;
  struct stack_entry *e;

  /* no pop on empty stack */
  if(!stack)
    return 0;

  /* amount of memory freed */
  size = sizeof(struct stack_entry) + stack->item.len;

  /* free/pop the item */
  e     = stack;
  stack = stack->next;
  free(e);

  return size;
}

void clean(void)
{
  struct stack_entry *e;

  while(stack) {
    e     = stack;
    stack = stack->next;
    free(e);
  }
}

int walk(int (*visit)(const struct gpushd_item *, void *), void *data)
{
  const struct stack_entry *e;

  for(e = stack ; e ; e = e->next) {
    int ret = visit(&e->item, data);
    if(ret)
      return ret;
  }

  return 0;
}

int is_empty(void)
{
  return stack == NULL;
}

uint64_t get_real_mem(void)
{
  /* FIXME: for now the implementation has no extra
            memory cost. so this function is disabled.
            we will use this for future implementation
            of the stack. */
  assert(0);

  return 0;
}
