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

#include <gawen/common.h>

#include "names.h"

static const char *error_major[] = {
  "stack error",
  "request parsing error"
};

static const char *error_minor[] = {
  "stack is full",
  "stack is empty",
  "invalid header length",
  "invalid request code"
};

static const char *response_names[] = {
  "Error response",
  "Field response",
  "Item response",
  "Info response",
  "Version response",
  "End response"
};

static const char *request_names[] = {
  "Push request",
  "Pop request",
  "Get request",
  "List request",
  "Info request",
  "Clean request",
  "Version request",
  "Extended version request"
};

const char * get_error_major(uint16_t major)
{
  if(major > sizeof_array(error_major))
    return NULL;
  return error_major[major];
}

const char * get_error_minor(uint16_t minor)
{
  if(minor > sizeof_array(error_minor))
    return NULL;
  return error_minor[minor];
}

const char * get_response_name(uint8_t response)
{
  if(response > sizeof_array(response_names))
    return NULL;
  return response_names[response];
}

const char * get_request_name(uint8_t request)
{
  if(request > sizeof_array(request_names))
    return NULL;
  return request_names[request];
}
