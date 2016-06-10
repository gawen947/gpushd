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
#include "common.h"
#include "version.h"
#include "iobuf.h"
#include "help.h"
#include "safe-call.h"

#define GPUSHD_SWAP_VERSION 3

enum s_magic {
  GPUSHD_SWAP_MAGIK1  = 0x48535047, /* GPSH */
  GPUSHD_SWAP_MAGIK2  = 0x50415753, /* SWAP */
};

/* various statistics */
static struct gpushd_stats stats = { .min_nsec = UINT64_MAX };

/* path to a swap file for the stack and statistics
   and the unix socket used for the server */
static const char *swap_path;
static const char *socket_path;

/* it is possible to return a default element when the stack is empty */
static unsigned int empty_len;
static const char *empty_item;

/* stack limit */
static unsigned int stack_entry_limit = DEFAULT_STACK_LIMIT;
static uint64_t     stack_mem_limit   = DEFAULT_MEM_LIMIT;

/* the stack contains the items */
static struct gpushd_item {
  struct gpushd_item *next;

  int len;
  char string[];
} *stack;


#define error_code(maj, min)                                   \
  (struct gpushd_error){ .major = GPUSHD_ERROR_MAJOR_ ## maj,  \
                         .minor = GPUSHD_ERROR_MINOR_ ## min }

#define send_end() send_response(req, GPUSHD_RES_END, NULL, 0)

#define entry_size(entry) sizeof(struct gpushd_item) + entry->len

#define NSEC 1000000000

static int timespec_substract(struct timespec *result, struct timespec *x, struct timespec *y)
{
  /* Perform the carry for the later subraction by updating y. */
  if (x->tv_nsec < y->tv_nsec) {
    int sec = (y->tv_nsec - x->tv_nsec) / NSEC + 1;
    y->tv_nsec -= NSEC * sec;
    y->tv_sec  += sec;
  }
  if (x->tv_nsec - y->tv_nsec > NSEC) {
    int sec = (x->tv_nsec - y->tv_nsec) / NSEC;
    y->tv_nsec += NSEC * sec;
    y->tv_sec  -= sec;
  }

  /* Compute the time remaining to wait.
     tv_usec is certainly positive. */
  result->tv_sec  = x->tv_sec - y->tv_sec;
  result->tv_nsec = x->tv_nsec - y->tv_nsec;

  /* Return 1 if result is negative. */
  return x->tv_sec < y->tv_sec;
}

static uint64_t substract_nsec(struct timespec *begin, struct timespec *end)
{
  struct timespec diff;
  uint64_t diff_nsec;

  /* Substract first and check that everything goes correctly. */
  int n = timespec_substract(&diff, end, begin);
  assert(!n);

  diff_nsec = diff.tv_sec * NSEC + diff.tv_nsec;

  return diff_nsec;
}

/* xiobuf*  calls abort the program in case of an error.
   xxiobuf* calls abort the program in case of an inconsistent read/write. */
static int xiobuf_close(iofile_t file)
{
  int ret = iobuf_close(file);
  if(ret < 0)
    err(EXIT_FAILURE, "iobuf_close");
  return ret;
}

static int xiobuf_read(iofile_t file, void *buf, size_t count)
{
  ssize_t ret = iobuf_read(file, buf, count);
  if(ret < 0)
    err(EXIT_FAILURE, "iobuf_read");
  return ret;
}

static void xxiobuf_write(iofile_t file, const void *buf, size_t count)
{
  ssize_t ret = iobuf_write(file, buf, count);
  if(ret != (ssize_t)count) {
    iobuf_close(file);
    err(EXIT_FAILURE, "iobuf_write");
  }
}

static void xxiobuf_read(iofile_t file, void *buf, size_t count)
{
  ssize_t ret = iobuf_read(file, buf, count);
  if(ret != (ssize_t)count) {
    iobuf_close(file);
    err(EXIT_FAILURE, "iobuf_read");
  }
}

/* Push an item to the stack but do not verify if we are at max size. */
static void push_to_stack(struct gpushd_item *item)
{
  item->next = stack;
  stack     = item;

  /* update statistics */
  stats.stack_size++;
  stats.stack_mem += entry_size(stack);
  if(stats.stack_size > stats.max_stack)
    stats.max_stack = stats.stack_size;
  if(stats.stack_mem > stats.max_mem)
    stats.max_mem = stats.stack_mem;
}

static void swap_save(void)
{
  const struct gpushd_item *item;
  uint32_t magik1  = GPUSHD_SWAP_MAGIK1;
  uint32_t magik2  = GPUSHD_SWAP_MAGIK2;
  uint32_t version = GPUSHD_SWAP_VERSION;
  iofile_t file;

  file = iobuf_open(swap_path, O_CREAT | O_WRONLY | O_TRUNC, 00666);
  if(!file) {
    warnx("cannot save swap file");
    return;
  }

  xxiobuf_write(file, &magik1,  sizeof(uint32_t));
  xxiobuf_write(file, &magik2,  sizeof(uint32_t));
  xxiobuf_write(file, &version, sizeof(uint32_t));

  xxiobuf_write(file, &stats, sizeof(struct gpushd_stats));

  for(item = stack ; item ; item = item->next) {
    uint16_t item_len = item->len;

    xxiobuf_write(file, &item_len, sizeof(uint16_t));
    xxiobuf_write(file, &item->string, item_len);
  }

  xiobuf_close(file);
}

static void swap_load_3(iofile_t file)
{
  uint16_t i;
  ssize_t n;

  /* Load the statistics we also have to reset some fields. */
  xxiobuf_read(file, &stats, sizeof(struct gpushd_stats));
  stats.stack_size = 0;
  stats.stack_mem  = 0;

  for(i = 0 ; i < stack_entry_limit ; i++) {
    uint16_t len;
    struct gpushd_item *item;

    /* Read a new item. If there is no more items the file ends here. */
    n = xiobuf_read(file, &len, sizeof(uint16_t));
    if(n == 0)
      return;

    /* allocate and read the item */
    item     = xmalloc(sizeof(struct gpushd_item) + len);
    item->len = len;

    xxiobuf_read(file, &item->string, len);

    /* push to stack */
    push_to_stack(item);

    /* check memory limit */
    if(stats.stack_mem > stack_mem_limit)
      break;
  }

  warnx("swap file too large for stack, remaining items not loaded");
}

static void swap_load(void)
{
  uint32_t magik1;
  uint32_t magik2;
  uint32_t version;
  iofile_t file;

  file = iobuf_open(swap_path, O_RDONLY, 00666);
  if(!file) {
    warnx("new swap file");
    return;
  }

  xxiobuf_read(file, &magik1, sizeof(uint32_t));
  xxiobuf_read(file, &magik2, sizeof(uint32_t));
  xxiobuf_read(file, &version, sizeof(uint32_t));

  if(magik1 != GPUSHD_SWAP_MAGIK1 || magik2 != GPUSHD_SWAP_MAGIK2) {
    warnx("invalid swap file");
    goto CLOSE;
  }

  if(version != GPUSHD_SWAP_VERSION)
    warnx("trying to migrate swap file from version %d to version %d", version, GPUSHD_SWAP_VERSION);

  switch(version) {
  case(1):
  case(2):
    warnx("version %d deprecated", version);
    break;
  case(3):
    swap_load_3(file);
    break;
  default:
    warnx("unknown swap file version %d", version);
    break;
  }

CLOSE:
  xiobuf_close(file);
}


static void sig_swap(int signum)
{
  UNUSED(signum);

  swap_save();
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
  swap_save();
}

static void send_response(const struct request_context *req, int code, const void *data, int len)
{
  static char message_buffer[MAX_MESSAGE_LEN];
  struct gpushd_message *message = (struct gpushd_message *)message_buffer;
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
    return;
  }

  stats.nb_responses[code]++;
  stats.nb_sent++;
}

static void send_error(const struct request_context *req, struct gpushd_error error)
{
  send_response(req, GPUSHD_RES_ERROR, &error, sizeof(struct gpushd_error));

  stats.nb_error++;
}

static void send_field(const struct request_context *req, const char *name, const char *value)
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

  send_response(req, GPUSHD_RES_FIELD, field_buffer, name_len + value_len + 1);
}


static void request_push(const struct request_context *req)
{
  int len = req->len;
  struct gpushd_item *item;

  /* check that the stack isn't full */
  if(stats.stack_size >= stack_entry_limit ||
     stats.stack_mem  >= stack_mem_limit) {
    send_error(req, error_code(STACK, FULL));
    return;
  }

  /* allocate the item */
  item      = xmalloc(sizeof(struct gpushd_item) + len);
  item->len = len;
  memcpy(item->string, req->data, len);

  /* push to stack */
  push_to_stack(item);

  send_end();
}

static void request_list(const struct request_context *req)
{
  const struct gpushd_item *item;

  for(item = stack ; item ; item = item->next)
    send_response(req, GPUSHD_RES_ITEM, item->string, item->len);

  if(empty_item)
    send_response(req, GPUSHD_RES_ITEM, empty_item, empty_len);

  send_end();
}

static void request_get(const struct request_context *req)
{
  int len;
  const char *string;

  /* manage the empty stack case */
  if(!stack) {
    if(!empty_item) {
      send_error(req, error_code(STACK, EMPTY));
      return;
    }

    string = empty_item;
    len    = empty_len;
  }
  else {
    string = stack->string;
    len    = stack->len;
  }

  send_response(req, GPUSHD_RES_ITEM, string, len);
}

static void request_pop(const struct request_context *req)
{
  struct gpushd_item *o;

  request_get(req);

  /* pop the item */
  if(stack) {
    stats.stack_size--;
    stats.stack_mem -= entry_size(stack);

    o     = stack;
    stack = stack->next;
    free(o);
  }
}

static void request_clean(const struct request_context *req)
{
  struct gpushd_item *o, *e;

  UNUSED(req);

  o = stack;

  while(o) {
    e = o;
    o = o->next;
    free(e);
  }

  stack = NULL;
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

  for(e = extended_version_fields ; e->name ; e++)
    send_field(req, e->name, e->value);
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
  int ttl = sync;

  struct sockaddr_un s_addr = { .sun_family = AF_UNIX };
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
    char buf[MAX_MESSAGE_LEN];
    int n;

    /* accept a new connection */
    int fd = accept(sd, NULL, NULL);
    if(fd < 0) {
      if(errno == EINTR)
        continue;
      err(EXIT_FAILURE, "accept()"); /* FIXME: use standard error message format (see client) */
    }

    /* read the message */
    n = recv(fd, buf, MAX_MESSAGE_LEN, 0);
    if(n < 0)
      err(EXIT_FAILURE, "network error"); /* FIXME: use standard error message */

    /* parse and compute parsing time */
    clock_gettime(CLOCK_MONOTONIC, &begin);
    parse(buf, n, fd);
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
    { 'S', "size",    "Maximum stack size (use 0 for no limit, default: 65k)" },
    { 'M', "memory",  "Maximum stack memory (use 0 for no limit, default: 128MB)" },
    { 0, NULL, NULL }
  };

  help(name, "[OPTIONS] SOCKET SWAP", messages);
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
  const char *prog_name;
  int exit_status = EXIT_FAILURE;
  int sync_ttl    = 0;

  struct option opts[] = {
    { "help", no_argument, NULL, 'h' },
    { "version", no_argument, NULL, 'V' },
    { "sync", required_argument, NULL, 's' },
    { "default", required_argument, NULL, 'd' },
    { "size", required_argument, NULL, 'S' },
    { "memory", required_argument, NULL, 'M' },
    { NULL, 0, NULL, 0 }
  };

  prog_name = basename(argv[0]);

  while(1) {
    int c = getopt_long(argc, argv, "hVs:d:S:M:", opts, NULL);

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
    case('S'):
      stack_entry_limit = atoi(optarg);
      break;
    case('M'):
      stack_mem_limit = atoi(optarg);
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

  if(argc != 2) {
    print_help(prog_name);
    goto EXIT;
  }

  socket_path = argv[0];
  swap_path   = argv[1];

  swap_load();
  stats.nb_server++;

  setup_signals();

  /* No limit is actually the maximum.
     That is ~4G entries and ~16 EiB.
     I'm sure it will be enough... */
  if(stack_entry_limit == 0)
    stack_entry_limit = -1;
  if(stack_mem_limit == 0)
    stack_mem_limit = -1;

  server(socket_path, sync_ttl);
  /* never return */

EXIT:
  exit(exit_status);
}
