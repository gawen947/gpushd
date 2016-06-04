/* Copyright (c) 2011-2016, David Hauweele <david@hauweele.net>
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

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <assert.h>

#include "gpushd-common.h"
#include "safe-call.h"
#include "common.h"
#include "help.h"

/* The first 7-bits of the waiting value represent
   the next message expected. The 8th bit specifies
   that we also accept an END message that marks the
   end of the response. */
#define WAITING_ACCEPT_END 1 << (8 + 0)

/* Timeout until request end */
#define REQUEST_TIMEOUT 1

#define DISPLAY_VALUE_BUFFER UINT8_MAX

static char *error_major[] = {
  "stack error",
  "request parsing error"
};

static char *error_minor[] = {
  "stack is full",
  "stack is empty",
  "invalid header length",
  "invalid request code"
};

static char *message_names[] = {
  "Error message",
  "Field message",
  "Item message",
  "Info message",
  "Version message",
  "End message"
};

static struct aligned_row {
  const char *description;
  const char *value;
  const char *unit;

  unsigned int len; /* description length */

  const struct aligned_row *next;
} *aligned_display;

int aligned_max_len = 0;

static void sig_timeout(int signum)
{
  fprintf(stderr, "server error: timeout\n");
  exit(EXIT_FAILURE);
}

static void xfree(void *ptr)
{
  if(ptr)
    free(ptr);
}

static void push_aligned_display(const char *description, const char *value, const char *unit)
{
  struct aligned_row *row = xmalloc(sizeof(struct aligned_row));
  int len = strlen(description);

  /* Push the new row on the list. */
  *row = (struct aligned_row){ description, value, unit,
                               len,
                               aligned_display };
  aligned_display = row;

  /* Compute the maximum length for the description field. */
  if(len > aligned_max_len)
    aligned_max_len = len;
}

static void commit_aligned_display(void)
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

static void response_info(const struct request_context *req)
{
  struct gpushd_stats *stats = (struct gpushd_stats *)req->data;
  char buffer[DISPLAY_VALUE_BUFFER];
  int i;

  snprintf(buffer, DISPLAY_VALUE_BUFFER, "%u", stats->max_stack);
  push_aligned_display("Maximum stack size", strdup(buffer), NULL);

  snprintf(buffer, DISPLAY_VALUE_BUFFER, "%u", stats->stack_size);
  push_aligned_display("Stack size", strdup(buffer), NULL);


  push_aligned_display(NULL, NULL, NULL);


  snprintf(buffer, DISPLAY_VALUE_BUFFER, "%lu", stats->sum_nsec);
  push_aligned_display("Total processing time", strdup(buffer), "ns");

  snprintf(buffer, DISPLAY_VALUE_BUFFER, "%lu", stats->min_nsec);
  push_aligned_display("Min processing time", strdup(buffer), "ns");

  snprintf(buffer, DISPLAY_VALUE_BUFFER, "%lu", stats->max_nsec);
  push_aligned_display("Max processing time", strdup(buffer), "ns");


  push_aligned_display(NULL, NULL, NULL);


  snprintf(buffer, DISPLAY_VALUE_BUFFER, "%lu", stats->nb_server);
  push_aligned_display("Server started", strdup(buffer), NULL);


  push_aligned_display(NULL, NULL, NULL);


  snprintf(buffer, DISPLAY_VALUE_BUFFER, "%lu", stats->nb_error);
  push_aligned_display("Number of error", strdup(buffer), NULL);

  for(i = (sizeof(stats->nb_messages) - 1) ; i >= 0 ; i--) {
    snprintf(buffer, DISPLAY_VALUE_BUFFER, "%lu", stats->nb_messages[i]);
    push_aligned_display(message_names[i], strdup(buffer), NULL);
  }

  snprintf(buffer, DISPLAY_VALUE_BUFFER, "%lu", stats->nb_error);
  push_aligned_display("Messages sent", strdup(buffer), NULL);


  commit_aligned_display();
}

static void response_item(const struct request_context *req)
{
  puts(req->data);
  fputc('\n', stdout);
}

static void response_version(const struct request_context *req)
{
  struct gpushd_version *version = (struct gpushd_version *)req->data;
  char buffer[DISPLAY_VALUE_BUFFER];

  snprintf(buffer, DISPLAY_VALUE_BUFFER, "v%u.%u", version->major, version->minor);
  push_aligned_display("server", strdup(buffer), NULL);

  snprintf(buffer, DISPLAY_VALUE_BUFFER, "%04x", version->protocol);
  push_aligned_display("protocol", strdup(buffer), NULL);

  snprintf(buffer, DISPLAY_VALUE_BUFFER, "%04x", version->swap);
  push_aligned_display("swap", strdup(buffer), NULL);

  commit_aligned_display();
}

static void response_field(const struct request_context *req)
{
  const char separator[] = ": ";
  char output[(UINT8_MAX << 1) + sizeof(separator)];
  char *out = output;

  unsigned int name_len  = ((unsigned char *)req->data)[0];
  unsigned int value_len = req->len - name_len - 1;

  const char *name  = req->data + 1;
  const char *value = name + name_len;

  memcpy(out, name, name_len);               out += name_len;
  memcpy(out, separator, sizeof(separator)); out += sizeof(separator);
  memcpy(out, value, value_len);             out += value_len;
  *out = '\n';

  puts(out);
}

static void response_error(const struct request_context *req)
{
  const struct gpushd_error *error = req->data;

  if(error->major > sizeof(error_major) || error->minor > sizeof(error_minor)) {
    /* FIXME: We need a special error code for this
              and a function dedicated to displaying errors. */
    fprintf(stderr, "response parsing error: invalid error code\n");
    return;
  }

  fprintf(stderr, "%s: %s\n", error_major[error->major], error_minor[error->minor]);
}

static int response(int waiting, struct request_context *req)
{
  /* this list must follow the order of the response message
     definition in the common header. we use the message code value
     to index the correct parsing function. */
  void (*response[])(const struct request_context *) = {
    NULL, /* error is captured earlier */
    response_field,
    response_item,
    response_info,
    response_version,
    NULL /* end is captured earlier */ };

  static char buffer[BUFFER_SIZE];
  struct gpushd_message *message = (struct gpushd_message *)buffer;
  int n;

  /* FIXME: use setsockopt() for timeout ? */
  n = recvfrom(req->socket, buffer, BUFFER_SIZE, 0, req->s_addr, &req->s_addrlen);
  if(n < 0)
    err(EXIT_FAILURE, "network error");

  if(message->id != req->request_id)
    errx(EXIT_FAILURE, "expected request id 0x%x but got 0x%x instead", req->request_id, message->id);

  n -= sizeof(struct gpushd_message);

  /* update request context */
  req->data = message->data;
  req->len  = n;

  switch(message->code) {
  case(GPUSHD_RES_END):
    if(waiting & WAITING_ACCEPT_END)
      return 0;
    else
      errx(EXIT_FAILURE, "unexpected end response");
  case(GPUSHD_RES_ERROR):
    response_error(req);
    assert(0); /* response_error must abort */
  default:
    break;
  }

  if(message->code != (waiting & 0xff))
    errx(EXIT_FAILURE, "expected response 0x%x but got 0x%x instead", waiting & 0xff, message->code);

  /* process response */
  response[message->code](req);

  /* if we do not accept an end message it means we have a single response */
  if(waiting & WAITING_ACCEPT_END)
    return waiting;
  else
    return 0;
}

static int send_request(const struct request_context *req, const char *command, const char *argument)
{
  static char message_buffer[BUFFER_SIZE];
  struct gpushd_message *message = (struct gpushd_message *)message_buffer;
  unsigned int len = 0;
  int waiting = 0;
  int argument_required = 0;

  message->id = req->request_id;

  /* TODO: we should use an optimized tree parser here */
  /* FIXME: parse the command and argument in another function. */
  if(!strcmp(command, "push")) {
    message->code = GPUSHD_REQ_PUSH;
    argument_required = 1;
  }
  else if(!strcmp(command, "pop")) {
    message->code = GPUSHD_REQ_POP;
    waiting      = GPUSHD_RES_ITEM;
  }
  else if(!strcmp(command, "get")) {
    message->code = GPUSHD_REQ_GET;
    waiting      = GPUSHD_RES_ITEM;
  }
  else if(!strcmp(command, "list")) {
    message->code  = GPUSHD_REQ_LIST;
    waiting       = GPUSHD_RES_ITEM;
    waiting      |= WAITING_ACCEPT_END;
  }
  else if(!strcmp(command, "info")) {
    message->code = GPUSHD_REQ_INFO;
    waiting      = GPUSHD_RES_INFO;
  }
  else if(!strcmp(command, "clean"))
    message->code = GPUSHD_REQ_CLEAN;
  else if(!strcmp(command, "version")) {
    message->code = GPUSHD_REQ_VERSION;
    waiting      = GPUSHD_RES_VERSION;
  }
  else if(!strcmp(command, "extver")) {
    message->code  = GPUSHD_REQ_EXTVER;
    waiting       = GPUSHD_RES_FIELD;
    waiting      |= WAITING_ACCEPT_END;
  }
  else {
    /* Display message list. */
    fprintf(stderr, "argument error: unknown command\n");
    fprintf(stderr, "Use one of the following:\n\n");

    push_aligned_display("push"   , NULL, "Push a value (argument required).");
    push_aligned_display("pop"    , NULL, "Pop a value.");
    push_aligned_display("get"    , NULL, "Get the value on top of the stack.");
    push_aligned_display("list"   , NULL, "List all entries.");
    push_aligned_display("info"   , NULL, "Display server statistics.");
    push_aligned_display("clean"  , NULL, "Remove all entries.");
    push_aligned_display("version", NULL, "Display server version.");
    push_aligned_display("extver" , NULL, "Display extended version information.");

    commit_aligned_display();

    exit(EXIT_FAILURE);
  }

  if(!argument && argument_required) {
    fprintf(stderr, "argument error: argument required\n");
    exit(EXIT_FAILURE);
  }
  else if (argument && !argument_required) {
    fprintf(stderr, "argument error: excess argument\n");
    exit(EXIT_FAILURE);
  }

  if(argument) {
    len = strlen(argument);

    /* The argument may be too long. */
    /* FIXME: We should check if argument is possible in the client. */
    /* FIXME: We should limit the length in the client. */
    if(len >= (BUFFER_SIZE - sizeof(struct gpushd_message))) {
      /* FIXME: use the dedicated error function */
      fprintf(stderr, "argument error: argument too long\n");
      exit(EXIT_FAILURE);
    }

    memcpy(message->data, argument, len);
  }

  sendto(req->socket, message, sizeof(struct gpushd_message) + len, 0, req->s_addr, req->s_addrlen);

  return waiting;
}

static void client(const char *socket_path, const char *command, const char *argument)
{
  struct request_context request;
  struct sigaction act_timeout = { .sa_handler = sig_timeout, .sa_flags   = 0 };
  struct sockaddr_un s_addr = { .sun_family = AF_UNIX,
                                .sun_len    = strlen(socket_path) };
  int waiting;

  /* limit request time */
  /* FIXME: use setsockopt() instead */
  sigfillset(&act_timeout.sa_mask);
  sigaction(SIGALRM, &act_timeout, NULL);
  alarm(REQUEST_TIMEOUT);

  /* socket creation */
  request.socket = xsocket(AF_UNIX, SOCK_DGRAM, 0);

  /* socket creation  */
  xstrcpy(s_addr.sun_path, socket_path, sizeof(s_addr.sun_path));

  /* assemble the rest of the request context */
  request.request_id = getpid();

  waiting = send_request(&request, command, argument);

  while(waiting)
    waiting = response(waiting, &request);
}

static void print_help(const char *name)
{
  struct opt_help messages[] = {
    { 'h', "help",    "Show this help message" },
    { 'V', "version", "Show version information" },
    { 0, NULL, NULL }
  };

  help(name, "[OPTIONS] SOCKET COMMAND COMMAND-ARGUMENT", messages);
}

int main(int argc, char *argv[])
{
  int exit_status      = EXIT_FAILURE;
  const char *argument = NULL;
  const char *command;
  const char *socket_path;
  const char *prog_name;

  struct option opts[] = {
    { "help", no_argument, NULL, 'h' },
    { "version", no_argument, NULL, 'V' },
    { NULL, 0, NULL, 0 }
  };

  prog_name = basename(argv[0]);

  while(1) {
    int c = getopt_long(argc, argv, "hV", opts, NULL);

    if(c == -1)
      break;
    switch(c) {
    case('V'):
      print_version(prog_name);
      exit_status = EXIT_SUCCESS;
      goto EXIT;
    case('h'):
      exit_status = EXIT_SUCCESS;
    default:
      print_help(prog_name);
      goto EXIT;
    }
  }

  argc -= optind;
  argv += optind;

  if(argc != 2 && argc != 3) {
    print_help(prog_name);
    goto EXIT;
  }

  socket_path = argv[0];
  command     = argv[1];

  if(argc == 3)
    argument = argv[2];

  /* Assemble the request, send it and parse the response.

     If there is an error during the process, the program
     is aborted as soon as possible. So we avoid moving up
     the error in return values. This way we avoid the need
     to handle negative values when the return value is used
     for some other purposes in the call path. */
  client(socket_path, command, argument);
  exit_status = EXIT_SUCCESS;

EXIT:
  exit(exit_status);
}
