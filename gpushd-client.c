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

#ifdef __linux__
# define _POSIX_C_SOURCE 200809L
#endif /* __linux__ */

#define __STDC_FORMAT_MACROS

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <assert.h>

#include "aligned-display.h"
#include "gpushd-common.h"
#include "safe-call.h"
#include "command.h"
#include "version.h"
#include "common.h"
#include "parser.h"
#include "buffer.h"
#include "names.h"
#include "scale.h"
#include "help.h"

#define DISPLAY_VALUE_BUFFER UINT8_MAX

/* Timeout value (in ms) */
static unsigned long timeout = DEFAULT_TIMEOUT;

/* Flag indicating the next message expected for the parser. */
static int waiting;

/* Specifies if we should use lines when using the list command. */
static int lines;

/* The functions we use to format value (depends on the --raw option). */
static const char * (*format_value)(uint64_t, const char *) = scale_metric;
static const char * (*format_time)(uint64_t) = scale_time;

static const char * raw_value(uint64_t value, const char *unit)
{
  static char buffer[DISPLAY_VALUE_BUFFER];

  if(unit)
    snprintf(buffer, DISPLAY_VALUE_BUFFER, "%"PRIu64" %s", value, unit);
  else
    snprintf(buffer, DISPLAY_VALUE_BUFFER, "%"PRIu64, value);

  return buffer;
}

static const char * raw_time(uint64_t value)
{
  return raw_value(value, "nsec");
}

static const char * limited_value(const char * (*format)(uint64_t, const char *),
                                  uint64_t value, uint64_t limit, uint64_t no_limit,
                                  const char *unit)
{
  static char buffer[DISPLAY_VALUE_BUFFER];
  char *s_value, *s_limit;

  if(limit == no_limit)
    return format(value, unit);

  s_value = strdup(format(value, unit));
  s_limit = strdup(format(limit, unit));

  snprintf(buffer, DISPLAY_VALUE_BUFFER, "%s / %s", s_value, s_limit);

  free(s_value);
  free(s_limit);

  return buffer;
}

static void response_info(const struct request_context *req)
{
  const char *value;
  struct gpushd_stats *stats = (struct gpushd_stats *)req->data;
  int i;


  value = limited_value(format_value, stats->stack_mem, stats->mem_limit, (uint64_t)-1, "B");
  push_aligned_display("Stack memory", strdup(value), ALC_VALUE);

  value = format_value(stats->max_mem, "B");
  push_aligned_display("Maximum memory", strdup(value), ALC_VALUE);


  push_aligned_display(NULL, NULL, 0);


  value = limited_value(raw_value, stats->stack_size, stats->entry_limit, (unsigned int)-1, NULL);
  push_aligned_display("Stack size", strdup(value), ALC_VALUE);

  value = raw_value(stats->max_stack, NULL);
  push_aligned_display("Maximum stack size", strdup(value), ALC_VALUE);


  push_aligned_display(NULL, NULL, 0);


  if(stats->sum_nsec == 0)
    value = "---";
  else
    value = format_time(stats->sum_nsec);
  push_aligned_display("Total processing time", strdup(value), ALC_VALUE);

  if(stats->min_nsec == UINT64_MAX)
    value = "---";
  else
    value = format_time(stats->min_nsec);
  push_aligned_display("Min processing time", strdup(value), ALC_VALUE);

  if(stats->max_nsec == 0)
    value = "---";
  else
    value = format_time(stats->max_nsec);
  push_aligned_display("Max processing time", strdup(value), ALC_VALUE);


  push_aligned_display(NULL, NULL, 0);


  for(i = (sizeof_array(stats->nb_requests) - 1) ; i >= 0 ; i--) {
    value = raw_value(stats->nb_requests[i], NULL);
    push_aligned_display(get_request_name(i), strdup(value), ALC_VALUE);
  }


  push_aligned_display(NULL, NULL, 0);


  for(i = (sizeof_array(stats->nb_responses) - 1) ; i >= 0 ; i--) {
    value = raw_value(stats->nb_responses[i], NULL);
    push_aligned_display(get_response_name(i), strdup(value), ALC_VALUE);
  }


  push_aligned_display(NULL, NULL, 0);


  value = raw_value(stats->nb_error, NULL);
  push_aligned_display("Number of error", strdup(value), ALC_VALUE);

  value = raw_value(stats->nb_sent, NULL);
  push_aligned_display("Messages sent", strdup(value), ALC_VALUE);

  value = raw_value(stats->nb_server, NULL);
  push_aligned_display("Server started", strdup(value), ALC_VALUE);
}

static void response_item(const struct request_context *req)
{
  if(lines)
    fprintf(stdout, "%d - ", lines++);
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
  case GPUSHD_RES_END:
    if(waiting & WAITING_ACCEPT_END)
      return 0;
    else
      errx(EXIT_FAILURE, "unexpected end response");
  case GPUSHD_RES_ERROR:
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

static int send_request(const struct command *cmd, const struct request_context *req)
{
  ssize_t ret;

  /* Assemble the message from the command. */
  if(cmd->argument)
    memcpy(message->data, cmd->argument, cmd->len);
  message->code = cmd->code;
  message->len  = cmd->len;

  /* FIXME: use a separate function for sending. */
  ret = send(req->fd, message, sizeof(struct gpushd_message) + cmd->len, 0);
  if(ret < 0) {
    perror("client error: send()");
    exit(EXIT_FAILURE);
  }

  return cmd->waiting;
}

static void client(const struct command *cmd, const char *socket_path)
{
  struct sockaddr_un s_addr = { .sun_family = AF_UNIX };
  struct timeval tv_timeout;
  struct request_context request;

  /* socket creation */
  xstrcpy(s_addr.sun_path, socket_path, sizeof(s_addr.sun_path));
  request.fd = xsocket(AF_UNIX, SOCK_STREAM, 0);

  /* connect to server */
  xconnect(request.fd, (struct sockaddr *)&s_addr, SUN_LEN(&s_addr));

  /* send request and wait for responses */
  waiting = send_request(cmd, &request);

  /* configure timeout limit */
  timeout           *= 1000; /* ms to us */
  tv_timeout = (struct timeval){ .tv_sec  = timeout / 1000000,
                                 .tv_usec = timeout % 1000000 };
  setsockopt(request.fd, SOL_SOCKET, SO_RCVTIMEO, &tv_timeout, sizeof(struct timeval));

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
#ifdef COMMIT
    { 0,   "commit",  "Display commit information" },
#endif /* COMMIT */
    { 'r', "raw",     "Do not scale values using time or metric units"},
    { 'T', "timeout", "Request timeout (in milliseconds, default: 100)" },
    { 'l', "line",    "Display line number when listing entries" },
    { 0, NULL, NULL }
  };

  help(name, "[OPTIONS] SOCKET COMMAND/help [COMMAND-ARGUMENT]", messages);
}

int main(int argc, char *argv[])
{
  struct command cmd;
  int exit_status      = EXIT_FAILURE;
  const char *argument = NULL;
  const char *command;
  const char *socket_path;
  const char *prog_name;

  enum opt {
    OPT_COMMIT = 0x100
  };

  struct option opts[] = {
    { "help", no_argument, NULL, 'h' },
    { "version", no_argument, NULL, 'V' },
#ifdef COMMIT
    { "commit", no_argument, NULL, OPT_COMMIT },
#endif /* COMMIT */
    { "raw", no_argument, NULL, 'r' },
    { "timeout", required_argument, NULL, 'T' },
    { NULL, 0, NULL, 0 }
  };

  prog_name = basename(argv[0]);

  while(1) {
    int c = getopt_long(argc, argv, "hVrT:l", opts, NULL);

    if(c == -1)
      break;
    switch(c) {
    case 'r':
      format_value = raw_value;
      format_time  = raw_time;
      break;
#ifdef COMMIT
    case OPT_COMMIT:
      commit();
      exit_status = EXIT_SUCCESS;
      goto EXIT;
#endif /* COMMIT */
    case 'V':
      version(prog_name);
      exit_status = EXIT_SUCCESS;
      goto EXIT;
    case 'T':
      timeout = atoi(optarg);
      break;
    case 'l':
      lines = 1;
      break;
    case 'h':
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

  /* Parse command */
  parse_command(&cmd, command, argument);

  /* Do not display lines number without the list command. */
  if(lines && strcmp(command, "list"))
    lines = 0;

  /* Assemble the request, send it and parse the response.

     If there is an error during the process, the program
     is aborted as soon as possible. So we avoid moving up
     the error in return values. This way we avoid the need
     to handle negative values when the return value is used
     for some other purposes in the call path. */
  client(&cmd, socket_path);
  exit_status = EXIT_SUCCESS;

EXIT:
  exit(exit_status);
}
