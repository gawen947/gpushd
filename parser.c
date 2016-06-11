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

#include <string.h>
#include <stdlib.h>
#include <err.h>

#include "gpushd-common.h"
#include "parser.h"

/* The states of the parser. */
static int parse_st_header(void);
static int parse_st_data(void);

/* Current state of the parser. */
static int (*parse_state_end)(void);

/* The message is assembled in this buffer. */
static char message_buffer[MAX_MESSAGE_LEN];
static struct gpushd_message *message = (struct gpushd_message *)message_buffer;

/* Data left to parse and pointer. */
static int   data_left;
static void *data_ptr;

/* Function to call when a message has been fully parsed.
   Along with a data pointer to pass to the function. */
static int (*message_parsed)(const struct gpushd_message *, void *);
static void *message_parsed_data;

static int parse_st_header(void)
{
  data_left       = message->len;
  parse_state_end = parse_st_data;

  /* If we don't need more data for this message
     we skip the parsing so the parser don't hang. */
  if(data_left == 0)
    return parse_st_data();

  return 1;
}

static int parse_st_data(void)
{
  /* Message parsed we re-init */
  data_left       = sizeof(struct gpushd_message);
  data_ptr        = message_buffer;
  parse_state_end = parse_st_header;

  return message_parsed(message, message_parsed_data);
}

void parse_init(int (*parsed)(const struct gpushd_message *message, void *data),
                       void *data)
{
  message_parsed      = parsed;
  message_parsed_data = data;

  data_left = sizeof(struct gpushd_message);
  data_ptr  = message_buffer;

  parse_state_end = parse_st_header;
}

int parse(const void *chunk, int size)
{
  int more = 1;
  const void *chunk_ptr = chunk;

  /* size | more
     0      0    => return no-more
     0      1    => return need-more
     1      0    => pending error
     1      1    => while
  */
  while(size) {
    /* How much should we copy? */
    int copy = data_left < size ? data_left : size;

    if(!more) /* the parsing completed but there are data pending */
      errx(EXIT_FAILURE, "invalid or pending response");

    memcpy(data_ptr, chunk_ptr, copy);

    /* Update pointers */
    data_ptr  += copy;
    chunk_ptr += copy;
    size      -= copy;
    data_left -= copy;

    if(data_left == 0)
      more = parse_state_end();
  }

  return more;
}
