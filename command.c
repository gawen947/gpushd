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
#include <string.h>
#include <assert.h>

#include <gawen/align.h>

#include "gpushd-common.h"
#include "command.h"

void parse_command(struct command *cmd, const char *command, const char *argument)
{
  int argument_required = 0;

  cmd->command  = command;
  cmd->argument = argument;
  cmd->waiting  = 0;
  cmd->len      = 0;

  /* TODO: we should use an optimized tree parser here */
  if(!strcmp(command, "help"))
    goto DISPLAY_LIST;
  if(!strcmp(command, "push")) {
    cmd->code     = GPUSHD_REQ_PUSH;
    cmd->waiting |= WAITING_ACCEPT_END;

    argument_required = 1;
  }
  else if(!strcmp(command, "pop")) {
    cmd->code    = GPUSHD_REQ_POP;
    cmd->waiting = GPUSHD_RES_ITEM;
  }
  else if(!strcmp(command, "get")) {
    cmd->code    = GPUSHD_REQ_GET;
    cmd->waiting = GPUSHD_RES_ITEM;
  }
  else if(!strcmp(command, "list")) {
    cmd->code     = GPUSHD_REQ_LIST;
    cmd->waiting  = GPUSHD_RES_ITEM;
    cmd->waiting |= WAITING_ACCEPT_END;
  }
  else if(!strcmp(command, "info")) {
    cmd->code    = GPUSHD_REQ_INFO;
    cmd->waiting = GPUSHD_RES_INFO;
  }
  else if(!strcmp(command, "clean")) {
    cmd->code     = GPUSHD_REQ_CLEAN;
    cmd->waiting |= WAITING_ACCEPT_END;
  }
  else if(!strcmp(command, "version")) {
    cmd->code    = GPUSHD_REQ_VERSION;
    cmd->waiting = GPUSHD_RES_VERSION;
  }
  else if(!strcmp(command, "extver")) {
    cmd->code     = GPUSHD_REQ_EXTVER;
    cmd->waiting  = GPUSHD_RES_FIELD;
    cmd->waiting  |= WAITING_ACCEPT_END;
  }
  else {
    /* Display message list. */
    fprintf(stderr, "argument error: unknown command\n");
    fprintf(stderr, "Use one of the following:\n\n");

  DISPLAY_LIST:
    push_aligned_display("push"   , "Push a value (argument required).", 0);
    push_aligned_display("pop"    , "Pop a value.", 0);
    push_aligned_display("get"    , "Get the value on top of the stack.", 0);
    push_aligned_display("list"   , "List all entries.", 0);
    push_aligned_display("info"   , "Display server statistics.", 0);
    push_aligned_display("clean"  , "Remove all entries.", 0);
    push_aligned_display("version", "Display server version.", 0);
    push_aligned_display("extver" , "Display extended version information.", 0);
    push_aligned_display("help"   , "List all available commands.", 0);

    commit_aligned_display(stdout);

    exit(EXIT_FAILURE);
  }

  /* All requests must have a response
     or at least expect an end message. */
  assert(cmd->waiting);

  /* Check if we require an argument or not. */
  if(!argument && argument_required) {
    fprintf(stderr, "argument error: argument required\n");
    exit(EXIT_FAILURE);
  }
  else if (argument && !argument_required) {
    fprintf(stderr, "argument error: excess argument\n");
    exit(EXIT_FAILURE);
  }

  if(argument) {
    cmd->len = strlen(argument);

    /* the argument may be too long */
    if(cmd->len >= MAX_DATA_LEN) {
      fprintf(stderr, "argument error: arument too long\n");
      exit(EXIT_FAILURE);
    }
  }
}
