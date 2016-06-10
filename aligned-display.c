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
#include <string.h>

#include "safe-call.h"
#include "common.h"
#include "aligned-display.h"

static struct aligned_row {
  const char *description;
  const char *value;
  const char *unit;

  unsigned int len; /* description length */

  const struct aligned_row *next;
} *aligned_display;

static int aligned_max_len = 0;

void push_aligned_display(const char *description, const char *value, const char *unit)
{
  struct aligned_row *row = xmalloc(sizeof(struct aligned_row));
  int len = description ? strlen(description) : 0;

  /* Push the new row on the list. */
  *row = (struct aligned_row){ description, value, unit,
                               len,
                               aligned_display };
  aligned_display = row;

  /* Compute the maximum length for the description field. */
  if(len > aligned_max_len)
    aligned_max_len = len;
}


void commit_aligned_display(void)
{
  const struct aligned_row *row;

  /* We already computed the maximum and the length for each element.
     So we pop them out and display to stdout. */
  for(row = aligned_display ; row ; row = row->next) {
    int size = row->len;

    /* An empty description means an empty row. */
    if(!row->description) {
      fputc('\n', stdout);
      continue;
    }

    fputs(row->description, stdout);

    for(; size <= aligned_max_len ; size++)
      fputc(' ', stdout);

    if(row->value) {
      fputs(": ", stdout);
      fputs(row->value, stdout);
    }

    if(row->unit) {
      fputc(' ', stdout);
      fputs(row->unit, stdout);
    }

    fputc('\n', stdout);
  }

  /* Now we can free everything.
     We also free the internal strings. */
  row = aligned_display;
  while(row) {
    const struct aligned_row *r = row;
    row = row->next;

    /* We only free the value as the other
       fields come from string literals. */
    xfree((void *)r->value);
    free((void *)r);
  }
}
