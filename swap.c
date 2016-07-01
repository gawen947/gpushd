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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <err.h>

#include "gpushd-common.h"
#include "statistics.h"
#include "buffer.h"
#include "stack.h"
#include "iobuf.h"
#include "swap.h"

enum s_magic {
  GPUSHD_SWAP_MAGIK1  = 0x48535047, /* GPSH */
  GPUSHD_SWAP_MAGIK2  = 0x50415753, /* SWAP */
};

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
  ssize_t ret = xiobuf_read(file, buf, count);
  if(ret != (ssize_t)count) {
    iobuf_close(file);
    errx(EXIT_FAILURE, "invalid swap file: file too short");
  }
}

static int swap_save_item(const struct gpushd_item *item, void *data)
{
  iofile_t file = (iofile_t)data;

  xxiobuf_write(file, &item->len, sizeof(uint16_t));
  xxiobuf_write(file, &item->data, item->len);

  return 0;
}

void swap_save(const char *swap_path)
{
  uint32_t magik1  = GPUSHD_SWAP_MAGIK1;
  uint32_t magik2  = GPUSHD_SWAP_MAGIK2;
  uint32_t version = GPUSHD_SWAP_VERSION;
  iofile_t file;

  /* report swap writing */
  printf("Saving swap... ");
  fflush(stdout);

  file = iobuf_open(swap_path, O_CREAT | O_WRONLY | O_TRUNC, 00666);
  if(!file) {
    warnx("cannot save swap file");
    return;
  }

  /* swap header */
  xxiobuf_write(file, &magik1,  sizeof(uint32_t));
  xxiobuf_write(file, &magik2,  sizeof(uint32_t));
  xxiobuf_write(file, &version, sizeof(uint32_t));

  /* statistics */
  xxiobuf_write(file, &stats, sizeof(struct gpushd_stats));

  /* write items */
  walk(swap_save_item, file);

  xiobuf_close(file);

  /* report swap written */
  printf("done!\n");
}

static void swap_load_3(iofile_t file, int reset, unsigned int *entry_limit, uint64_t *mem_limit)
{
  uint16_t i;
  ssize_t n;

  /* Load the statistics we also have to reset some fields. */
  if(!reset)
    xxiobuf_read(file, &stats, sizeof(struct gpushd_stats));
  else
    iobuf_lseek(file, sizeof(struct gpushd_stats), SEEK_CUR);
  stats.stack_size = 0;
  stats.stack_mem  = 0;

  /* If the limit were not configured from the command line
     we use the value from the swap file instead. */
  if(*entry_limit == 0)
    *entry_limit = stats.entry_limit;
  if(*mem_limit == 0)
    *mem_limit = stats.mem_limit;

  for(i = 0 ; i <= *entry_limit ; i++) {
    /* Read a new item. If there is no more items the file ends here. */
    n = xiobuf_read(file, &message->len, sizeof(message->len));
    if(n == 0)
      return;
    xxiobuf_read(file, &message->data, message->len);

    /* Push and update statistics. */
    PUSH(message->data, message->len);

    /* check memory limit */
    if(stats.stack_mem > *mem_limit)
      break;
  }

  warnx("swap file too large for stack, remaining items not loaded");
}

void swap_load(const char *swap_path, int reset, unsigned int *entry_limit, uint64_t *mem_limit)
{
  uint32_t magik1;
  uint32_t magik2;
  uint32_t version;
  iofile_t file;

  /* report swap loading */
  printf("Loading swap... ");
  fflush(stdout);

  file = iobuf_open(swap_path, O_RDONLY, 00666);
  if(!file) {
    warnx("new swap file");
    return;
  }

  xxiobuf_read(file, &magik1, sizeof(uint32_t));
  xxiobuf_read(file, &magik2, sizeof(uint32_t));
  xxiobuf_read(file, &version, sizeof(uint32_t));

  if(magik1 != GPUSHD_SWAP_MAGIK1 || magik2 != GPUSHD_SWAP_MAGIK2) {
    warnx("invalid swap file: invalid magik number");
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
    swap_load_3(file, reset, entry_limit, mem_limit);
    break;
  default:
    warnx("unknown swap file version %d", version);
    break;
  }

  /* report swap loaded */
  printf("done!\n");

CLOSE:
  xiobuf_close(file);
}
