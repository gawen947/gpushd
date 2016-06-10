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

#ifndef _GPUSHD_COMMON_H_

#include <sys/socket.h>
#include <stdint.h>

#include "iobuf.h"

#define UNUSED(x) (void)(x)
#define sizeof_array(x) (sizeof(x) / sizeof((x)[0]))

/* Maximum length of a single message. */
#define MAX_MESSAGE_LEN UINT16_MAX + sizeof(struct gpushd_message)

/* Maximum data length. */
#define MAX_DATA_LEN    MAX_MESSAGE_LEN - sizeof(struct gpushd_message)

/* Size of the receive buffer */
/* FIXME: Should be equal to MAX_MESSAGE_LEN we use a smaller value just for testing. */
#define RECEIVE_BUFFER_SIZE MAX_MESSAGE_LEN

#define MAX_RES_CODE GPUSHD_RES_END
#define MAX_REQ_CODE GPUSHD_REQ_EXTVER
#define MAX_STACK        (uint16_t)-1

enum {
  GPUSHD_RES_ERROR,
  GPUSHD_RES_FIELD,
  GPUSHD_RES_ITEM,
  GPUSHD_RES_INFO,
  GPUSHD_RES_VERSION,
  GPUSHD_RES_END /* should be the last */
};

enum {
  GPUSHD_REQ_PUSH,
  GPUSHD_REQ_POP,
  GPUSHD_REQ_GET,
  GPUSHD_REQ_LIST,
  GPUSHD_REQ_INFO,
  GPUSHD_REQ_CLEAN,
  GPUSHD_REQ_VERSION,
  GPUSHD_REQ_EXTVER /* should be the last */
};

enum {
  GPUSHD_ERROR_MAJOR_STACK,
  GPUSHD_ERROR_MAJOR_PARSING
};

enum {
  GPUSHD_ERROR_MINOR_FULL,
  GPUSHD_ERROR_MINOR_EMPTY,
  GPUSHD_ERROR_MINOR_HEADER_LEN,
  GPUSHD_ERROR_MINOR_CODE
};

struct gpushd_stats {
  /* number of messages sent */
  unsigned long nb_sent;
  unsigned long nb_requests[MAX_REQ_CODE];
  unsigned long nb_responses[MAX_RES_CODE];

  /* number of error */
  unsigned long nb_error;

  /* number of servers started */
  unsigned long nb_server;

  /* request time */
  uint64_t max_nsec;
  uint64_t min_nsec;
  uint64_t sum_nsec;

  /* information about the stack */
  unsigned int stack_size;
  unsigned int max_stack;
};

struct gpushd_version {
  uint16_t major;
  uint16_t minor;
  uint16_t protocol;
  uint16_t swap;
};

struct gpushd_error {
  uint16_t major;
  uint16_t minor;
};

struct gpushd_message {
  uint8_t  code; /* message code */
  uint16_t len;  /* data length */
  unsigned char data[];
};

struct request_context {
  const void *data;    /* message data */
  int len;             /* data length */

  int fd;          /* file descriptor of the connection */
  iofile_t stream; /* buffered connection */
};

#endif /* _GPUSHD_COMMON_H_ */
