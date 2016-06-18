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

#include "aligned-display.h"
#include "gpushd-common.h"
#include "safe-call.h"
#include "common.h"
#include "parser.h"
#include "buffer.h"
#include "names.h"
#include "scale.h"
#include "help.h"

/* The first 7-bits of the waiting value represent
   the next message expected. The 8th bit specifies
   that we also accept an END message that marks the
   end of the response. */
#define WAITING_ACCEPT_END 1 << (8 + 0)

/* Timeout until request end */
#define REQUEST_TIMEOUT 1

#define DISPLAY_VALUE_BUFFER UINT8_MAX

/* Flag indicating the next message expected for the parser. */
static int waiting;

static void sig_timeout(int signum)
{
  UNUSED(signum);

  fprintf(stderr, "server error: timeout\n");
  exit(EXIT_FAILURE);
}

static void response_info(const struct request_context *req)
{
  const char *scaled;
  struct gpushd_stats *stats = (struct gpushd_stats *)req->data;
  char buffer[DISPLAY_VALUE_BUFFER];
  int i;

  scaled = scale_metric(stats->mem_limit, "B");
  push_aligned_display("Memory limit", strdup(scaled), ALC_VALUE);

  scaled = scale_metric(stats->stack_mem, "B");
  push_aligned_display("Stack memory", strdup(scaled), ALC_VALUE);

  scaled = scale_metric(stats->max_mem, "B");
  push_aligned_display("Maximum memory", strdup(scaled), ALC_VALUE);


  push_aligned_display(NULL, NULL, 0);


  snprintf(buffer, DISPLAY_VALUE_BUFFER, "%u", stats->entry_limit);
  push_aligned_display("Stack limit", strdup(buffer), ALC_VALUE);

  snprintf(buffer, DISPLAY_VALUE_BUFFER, "%u", stats->stack_size);
  push_aligned_display("Stack size", strdup(buffer), ALC_VALUE);

  snprintf(buffer, DISPLAY_VALUE_BUFFER, "%u", stats->max_stack);
  push_aligned_display("Maximum stack size", strdup(buffer), ALC_VALUE);


  push_aligned_display(NULL, NULL, 0);


  if(stats->sum_nsec == 0) {
    snprintf(buffer, DISPLAY_VALUE_BUFFER, "---");
    scaled = buffer;
  }
  else
    scaled = scale_time(stats->sum_nsec);
  push_aligned_display("Total processing time", strdup(scaled), ALC_VALUE);

  if(stats->min_nsec == UINT64_MAX) {
    snprintf(buffer, DISPLAY_VALUE_BUFFER, "---");
    scaled = buffer;
  }
  else
    scaled = scale_time(stats->min_nsec);
  push_aligned_display("Min processing time", strdup(scaled), ALC_VALUE);

  if(stats->max_nsec == 0) {
    snprintf(buffer, DISPLAY_VALUE_BUFFER, "---");
    scaled = buffer;
  }
  else
    scaled = scale_time(stats->max_nsec);
  push_aligned_display("Max processing time", strdup(scaled), ALC_VALUE);


  push_aligned_display(NULL, NULL, 0);


  for(i = (sizeof_array(stats->nb_requests) - 1) ; i >= 0 ; i--) {
    snprintf(buffer, DISPLAY_VALUE_BUFFER, "%lu", stats->nb_requests[i]);
    push_aligned_display(get_request_name(i), strdup(buffer), ALC_VALUE);
  }


  push_aligned_display(NULL, NULL, 0);


  for(i = (sizeof_array(stats->nb_responses) - 1) ; i >= 0 ; i--) {
    snprintf(buffer, DISPLAY_VALUE_BUFFER, "%lu", stats->nb_responses[i]);
    push_aligned_display(get_response_name(i), strdup(buffer), ALC_VALUE);
  }


  push_aligned_display(NULL, NULL, 0);


  snprintf(buffer, DISPLAY_VALUE_BUFFER, "%lu", stats->nb_error);
  push_aligned_display("Number of error", strdup(buffer), ALC_VALUE);

  snprintf(buffer, DISPLAY_VALUE_BUFFER, "%lu", stats->nb_sent);
  push_aligned_display("Messages sent", strdup(buffer), ALC_VALUE);

  snprintf(buffer, DISPLAY_VALUE_BUFFER, "%lu", stats->nb_server);
  push_aligned_display("Server started", strdup(buffer), ALC_VALUE);
}

static void response_item(const struct request_context *req)
{
  fwrite(req->data, req->len, 1, stdout);
  fputc('\n', stdout);
}

static void response_version(const struct request_context *req)
{
  struct gpushd_version *version = (struct gpushd_version *)req->data;
  char buffer[DISPLAY_VALUE_BUFFER];

  snprintf(buffer, DISPLAY_VALUE_BUFFER, "v%u.%u", version->major, version->minor);
  push_aligned_display("server", strdup(buffer), ALC_VALUE);

  snprintf(buffer, DISPLAY_VALUE_BUFFER, "%04x", version->protocol);
  push_aligned_display("protocol", strdup(buffer), ALC_VALUE);

  snprintf(buffer, DISPLAY_VALUE_BUFFER, "%04x", version->swap);
  push_aligned_display("swap", strdup(buffer), ALC_VALUE);
}

static void response_field(const struct request_context *req)
{
  unsigned int name_len  = ((unsigned char *)req->data)[0];
  unsigned int value_len = req->len - name_len - 1;

  const char *name  = req->data + 1;
  const char *value = name + name_len;

  push_aligned_display(strndup(name, name_len),
                       strndup(value, value_len),
                       ALC_DESC | ALC_VALUE);
}

static void response_error(const struct request_context *req)
{
  const struct gpushd_error *error = req->data;
  const char *major_str = get_error_major(error->major);
  const char *minor_str = get_error_minor(error->minor);

  if(!major_str || !minor_str) {
    /* FIXME: We need a special error code for this
              and a function dedicated to displaying errors. */
    fprintf(stderr, "response parsing error: invalid error code\n");
    return;
  }

  fprintf(stderr, "%s: %s\n", major_str, minor_str);

  /* response error must abort */
  exit(EXIT_FAILURE);
}

static int parsed(const struct gpushd_message *message, void *data)
{
  struct request_context *req = (struct request_context *)data;

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

  /* update request context */
  /* FIXME: put the message directly */
  req->data = message->data;
  req->len  = message->len;

  /* special messages */
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

static void recv_response(struct request_context *req)
{
  static char receive_buffer[RECEIVE_BUFFER_SIZE];
  int n, more = 1;

  parse_init(parsed, req);

  while(more) {
    /* FIXME: use  setsockopt() for timeout ? */
    n = recv(req->fd, receive_buffer, RECEIVE_BUFFER_SIZE, 0);
    if(n < 0)
      err(EXIT_FAILURE, "network error");
    else if(n == 0)
      errx(EXIT_FAILURE, "connection aborted");

    /* The messages are passed on a stream unix socket.
       However we might receive multiple messages at once
       that fall out of the receive buffer. So we pass them
       to a parsing function that will copy each message
       one by one in a message buffer and then process them.
       This function aborts the program in case of a parsing
       error and return if there are more byte expected to
       finish the messages. */
    more = parse(receive_buffer, n);
  }
}

static int send_request(const struct request_context *req, const char *command, const char *argument)
{
  unsigned int len = 0;
  int waiting = 0;
  int argument_required = 0;
  ssize_t ret;

  /* TODO: we should use an optimized tree parser here */
  /* FIXME: parse the command and argument in another function. */
  if(!strcmp(command, "push")) {
    message->code = GPUSHD_REQ_PUSH;
    waiting     |= WAITING_ACCEPT_END;

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
  else if(!strcmp(command, "clean")) {
    message->code = GPUSHD_REQ_CLEAN;
    waiting     |= WAITING_ACCEPT_END;
  }
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

    push_aligned_display("push"   , "Push a value (argument required).", 0);
    push_aligned_display("pop"    , "Pop a value.", 0);
    push_aligned_display("get"    , "Get the value on top of the stack.", 0);
    push_aligned_display("list"   , "List all entries.", 0);
    push_aligned_display("info"   , "Display server statistics.", 0);
    push_aligned_display("clean"  , "Remove all entries.", 0);
    push_aligned_display("version", "Display server version.", 0);
    push_aligned_display("extver" , "Display extended version information.", 0);

    commit_aligned_display();

    exit(EXIT_FAILURE);
  }

  /* All requests must have a reponse
     or at least expect an end message. */
  assert(waiting);

  /* FIXME: this check should be done before we create the connection */
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
    if(len >= MAX_DATA_LEN) {
      /* FIXME: use the dedicated error function */
      fprintf(stderr, "argument error: argument too long\n");
      exit(EXIT_FAILURE);
    }

    memcpy(message->data, argument, len);
  }

  /* Now that the message is assembled we can set the len field. */
  message->len = len;

  /* FIXME: use a separate function for sending. */
  ret = send(req->fd, message, sizeof(struct gpushd_message) + len, 0);
  if(ret < 0) {
    perror("client error: send()");
    exit(EXIT_FAILURE);
  }

  return waiting;
}

static void client(const char *socket_path, const char *command, const char *argument)
{
  struct request_context request;
  struct sigaction act_timeout = { .sa_handler = sig_timeout, .sa_flags   = 0 };
  struct sockaddr_un s_addr = { .sun_family = AF_UNIX };

  /* limit request time */
  /* FIXME: use setsockopt() instead */
  sigfillset(&act_timeout.sa_mask);
  sigaction(SIGALRM, &act_timeout, NULL);
  alarm(REQUEST_TIMEOUT);

  /* socket creation */
  xstrcpy(s_addr.sun_path, socket_path, sizeof(s_addr.sun_path));
  request.fd = xsocket(AF_UNIX, SOCK_STREAM, 0);

  /* connect to server */
  xconnect(request.fd, (struct sockaddr *)&s_addr, SUN_LEN(&s_addr));

  /* send request and wait for responses */
  waiting = send_request(&request, command, argument);

  /* We only parse the response when needed. */
  if(waiting)
    recv_response(&request);

  /* If we used the aligned display, we display it now. */
  commit_aligned_display();
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
