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
#include <getopt.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <err.h>

#include "gpushd-common.h"
#include "time-substract.h"
#include "statistics.h"
#include "common.h"
#include "version.h"
#include "iobuf.h"
#include "stack.h"
#include "swap.h"
#include "buffer.h"
#include "help.h"
#include "safe-call.h"

/* Timeout until request end */
#define REQUEST_TIMEOUT 1

/* path to a swap file for the stack and statistics
   and the unix socket used for the server */
static const char *swap_path;
static const char *socket_path;

/* it is possible to return a default element when the stack is empty */
static unsigned int empty_len;
static const char *empty_item;

/* disable swap */
static int no_swap;

#define error_code(maj, min)                                   \
  (struct gpushd_error){ .major = GPUSHD_ERROR_MAJOR_ ## maj,  \
                         .minor = GPUSHD_ERROR_MINOR_ ## min }

#define send_end() send_response(req, GPUSHD_RES_END, NULL, 0)

static void sig_swap(int signum)
{
  UNUSED(signum);

  if(!no_swap)
    swap_save(swap_path);
}

static void sig_term(int signum)
{
  UNUSED(signum);
  exit(0);
}

static void exit_clean(void)
{
  printf("exiting...\n");
  unlink(socket_path);

  if(!no_swap)
    swap_save(swap_path);
}

static int send_response(const struct request_context *req, int code, const void *data, int len)
{
  ssize_t ret;

  /* build the message */
  message->code = code;
  message->len  = len;

  if(data)
    memcpy(message->data, data, len);

  /* send the message */
  ret = iobuf_write(req->stream, message, sizeof(struct gpushd_message) + len);
  if(ret < 0) {
    perror("server error: send()");
    return -1;
  }

  stats.nb_responses[code]++;
  stats.nb_sent++;

  return 0;
}

static int send_error(const struct request_context *req, struct gpushd_error error)
{
  stats.nb_error++;
  return send_response(req, GPUSHD_RES_ERROR, &error, sizeof(struct gpushd_error));
}

static int send_field(const struct request_context *req, const char *name, const char *value)
{
  static char field_buffer[(UINT8_MAX << 1) + 1];
  int name_len, value_len;

  name_len  = strlen(name);
  value_len = strlen(value);

  assert(name_len  <= 0xff);
  assert(value_len <= 0xff);

  /* field format: [name_len][name][value] */
  field_buffer[0] = name_len;
  memcpy(field_buffer + 1           , name , name_len);
  memcpy(field_buffer + 1 + name_len, value, value_len);

  return send_response(req, GPUSHD_RES_FIELD, field_buffer, name_len + value_len + 1);
}


static void request_push(const struct request_context *req)
{
  /* check that the stack isn't full */
  if(stats.stack_size >= stats.entry_limit ||
     stats.stack_mem  >= stats.mem_limit) {
    send_error(req, error_code(STACK, FULL));
    return;
  }

  /* push and update statistics */
  PUSH(req->data, req->len);

  send_end();
}

static int request_list_send_item(const struct gpushd_item *item, void *data)
{
  const struct request_context *req = data;

  return send_response(req, GPUSHD_RES_ITEM, item->data, item->len);
}

static void request_list(const struct request_context *req)
{
  /* abort when connection fail */
  if(walk(request_list_send_item, (void *)req) < 0)
    return;

  if(empty_item)
    send_response(req, GPUSHD_RES_ITEM, empty_item, empty_len);

  send_end();
}

/* Does the get request but return zero if the stack is empty. */
static int request_get_helper(const struct request_context *req)
{
  int len;
  const char *data;
  const struct gpushd_item *item = get();

  /* manage empty stack case */
  if(!item) {
    if(!empty_item) {
      send_error(req, error_code(STACK, EMPTY));
      return 0;
    }

    data = empty_item;
    len  = empty_len;
  }
  else {
    data = item->data;
    len  = item->len;
  }

  send_response(req, GPUSHD_RES_ITEM, data, len);

  return 1;
}

static void request_get(const struct request_context *req)
{
  (void)request_get_helper(req);
}

static void request_pop(const struct request_context *req)
{
  if(request_get_helper(req))
    POP();
}

static void request_clean(const struct request_context *req)
{
  UNUSED(req);

  clean();

  /* update statistics */
  stats.stack_size = 0;
  stats.stack_mem  = 0;

  send_end();
}

static void request_info(const struct request_context *req)
{
  send_response(req, GPUSHD_RES_INFO, &stats, sizeof(struct gpushd_stats));
}

static void request_version(const struct request_context *req)
{
  struct gpushd_version version = {
    .major    = GPUSHD_MAJOR_VERSION,
    .minor    = GPUSHD_MINOR_VERSION,
    .protocol = GPUSHD_PROTOCOL_VERSION,
    .swap     = GPUSHD_SWAP_VERSION };

  send_response(req, GPUSHD_RES_VERSION, &version, sizeof(struct gpushd_version));
}

static void request_extver(const struct request_context *req)
{
  const struct {
    const char *name;
    const char *value;
  } extended_version_fields[] = {
    { "version",  VERSION },
#ifdef COMMIT
    { "commit",   COMMIT },
#endif /* COMMIT */
    { "protocol", stringify(GPUSHD_PROTOCOL_VERSION) },
    { "swap",     stringify(GPUSHD_SWAP_VERSION) },
    { "author",   GPUSHD_AUTHOR },
    { "mail",     GPUSHD_MAIL },
    { "website",  GPUSHD_WEBSITE },
    { "license",  GPUSHD_LICENSE },
    { NULL, NULL }
  }, *e;

  for(e = extended_version_fields ; e->name ; e++) {
    if(send_field(req, e->name, e->value) < 0)
      return;
  }
  send_end();
}

static void parse(const char *buf, int len, int fd)
{
  /* this list must follow the order of the request message
     definition in the common header. we use the message code value
     to index the correct parsing function. */
  void (*request[])(const struct request_context *) = {
    request_push,
    request_pop,
    request_get,
    request_list,
    request_info,
    request_clean,
    request_version,
    request_extver };

  const struct gpushd_message *message = (const struct gpushd_message *)buf;
  struct request_context context;

  /* Compute data length and check the len field of the message.
     We should only receive one request at a time on the socket.
     If we receive multiple messages, we skip them all. */
  len -= sizeof(struct gpushd_message);
  if(len != message->len) {
    warnx("invalid or pending requests");
    return;
  }

  /* assemble the request context */
  context.data   = message->data;
  context.len    = len;
  context.stream = iobuf_dopen(fd);

  /* check the length of the header */
  if(len < 0) {
    send_error(&context, error_code(PARSING, HEADER_LEN));
    return;
  }

  /* check that the message code is valid */
  if(message->code > sizeof_array(request)) {
    send_error(&context, error_code(PARSING, CODE));
    return;
  }

  /* parse the message according to the message code.
     note that we don't use any condition to do that. */
  stats.nb_requests[message->code]++;
  request[message->code](&context);

  /* close the context */
  iobuf_close(context.stream);
}

static void report_request_time(struct timespec *begin, struct timespec *end)
{
  uint64_t request_nsec = substract_nsec(begin, end);

  if(request_nsec > stats.max_nsec)
    stats.max_nsec = request_nsec;
  if(request_nsec < stats.min_nsec)
    stats.min_nsec = request_nsec;

  stats.sum_nsec += request_nsec;
}

static void server(const char *socket_path, int sync)
{
  struct timeval timeout = { REQUEST_TIMEOUT, 0 };
  struct sockaddr_un s_addr = { .sun_family = AF_UNIX };
  int ttl = sync;
  int sd;

  /* socket creation */
  sd = xsocket(AF_UNIX, SOCK_STREAM, 0);

  /* bind to the specified unix socket */
  unlink(socket_path);
  xstrcpy(s_addr.sun_path, socket_path, sizeof(s_addr.sun_path));
  xbind(sd, (struct sockaddr *)&s_addr, SUN_LEN(&s_addr));

  /* now we may register the exit function */
  atexit(exit_clean);

  /* listen and backlog up to four connections */
  xlisten(sd, 4);

  while(1) {
    struct timespec begin, end;
    int n;

    /* accept a new connection */
    int fd = accept(sd, NULL, NULL);
    if(fd < 0) {
      if(errno == EINTR)
        continue;
      err(EXIT_FAILURE, "accept()"); /* FIXME: use standard error message format (see client) */
    }

    /* configure timeout limit */
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval));

    /* read the message */
    n = recv(fd, message_buffer, MAX_MESSAGE_LEN, 0);
    if(n < 0)
      err(EXIT_FAILURE, "network error"); /* FIXME: use standard error message */

    /* parse and compute parsing time */
    clock_gettime(CLOCK_MONOTONIC, &begin);
    parse(message_buffer, n, fd);
    clock_gettime(CLOCK_MONOTONIC, &end);

    /* statistics */
    report_request_time(&begin, &end);

    /* swap when needed */
    if(ttl-- == 0 && sync) {
      sig_swap(0);
      ttl = sync;
    }
  }
}

static void print_help(const char *name)
{
  struct opt_help messages[] = {
    { 'h', "help",    "Show this help message" },
    { 'V', "version", "Show version information" },
    { 's', "sync",    "Sync after a number of request" },
    { 'd', "default", "Default value for an empty stack" },
    { 'n', "no-swap", "Do not use a swap file" },
    { 'S', "size",    "Maximum stack size (use 0 for no limit, default: 65k)" },
    { 'M', "memory",  "Maximum stack memory (use 0 for no limit, default: 128MB)" },
    { 'R', "reset",   "Reset statistics" },
    { 0, NULL, NULL }
  };

  help(name,
       no_swap ? "[OPTIONS] SOCKET" : "[OPTIONS] SOCKET SWAP",
       messages);
}

static void setup_siglist(int signals[], struct sigaction *act, int size)
{
  int i;

  sigfillset(&act->sa_mask);
  for(i = 0 ; i < size ; i++)
    sigaction(signals[i], act, NULL);
}

static void setup_signals(void)
{
  struct sigaction act_swap = { .sa_handler = sig_swap, .sa_flags = 0 };
  struct sigaction act_term = { .sa_handler = sig_term, .sa_flags = 0 };
  struct sigaction act_ign  = { .sa_handler = SIG_IGN,  .sa_flags = 0 };

  int signals_term[] = {
    SIGHUP,
    SIGINT,
    SIGTERM };

  int signals_swap[] = {
    SIGUSR1,
    SIGUSR2 };

  int signals_ign[] = {
    SIGPIPE /* raised when client broke pipe */
  };

  setup_siglist(signals_term, &act_term, sizeof_array(signals_term));
  setup_siglist(signals_swap, &act_swap, sizeof_array(signals_swap));
  setup_siglist(signals_ign, &act_ign, sizeof_array(signals_ign));
}

int main(int argc, char *argv[])
{
  const char   *prog_name;
  unsigned int  entry_limit = 0; /* 0 is not-set */
  uint64_t      mem_limit   = 0;
  int           exit_status = EXIT_FAILURE;
  int           sync_ttl    = 0;
  int           reset       = 0;

  struct option opts[] = {
    { "help", no_argument, NULL, 'h' },
    { "version", no_argument, NULL, 'V' },
    { "sync", required_argument, NULL, 's' },
    { "default", required_argument, NULL, 'd' },
    { "no-swap", no_argument, NULL, 'n' },
    { "size", required_argument, NULL, 'S' },
    { "memory", required_argument, NULL, 'M' },
    { "reset", no_argument, NULL, 'R' },
    { NULL, 0, NULL, 0 }
  };

  prog_name = basename(argv[0]);

  while(1) {
    int c = getopt_long(argc, argv, "hVs:d:nS:M:R", opts, NULL);

    if(c == -1)
      break;

    switch(c) {
    case('s'):
      sync_ttl = atoi(optarg);
      if(sync < 0)
        errx(EXIT_FAILURE, "invalid number of request");
      break;
    case('d'):
      empty_item = optarg;
      empty_len  = strlen(optarg);
      break;
    case('n'):
      no_swap = 1;
      break;
    case('S'):
      entry_limit = atoi(optarg);

      /* No limit (0) is actually the maximum.
         That is ~4G entries and ~16 EiB.
         I'm sure it will be enough... */
      if(entry_limit == 0)
        entry_limit = -1;
      break;
    case('M'):
      mem_limit = atoi(optarg);
      if(mem_limit == 0)
        mem_limit = -1;
      break;
    case ('R'):
      reset = 1;
      break;
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

  if(argc != (no_swap ? 1 : 2)) {
    print_help(prog_name);
    goto EXIT;
  }

  socket_path = argv[0];
  swap_path   = argv[1];

  if(!no_swap)
    swap_load(swap_path, reset, &entry_limit, &mem_limit);
  stats.nb_server++;

  setup_signals();

  /* if the limit were not set from the swap or cli
     we set it to the default value */
  if(entry_limit == 0)
    entry_limit = DEFAULT_ENTRY_LIMIT;
  if(mem_limit == 0)
    mem_limit = DEFAULT_MEM_LIMIT;

  /* report the limit into the stats context */
  stats.entry_limit = entry_limit;
  stats.mem_limit   = mem_limit;

  server(socket_path, sync_ttl);
  /* never return */

EXIT:
  exit(exit_status);
}
