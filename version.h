/* Copyright (c) 2013-2016, David Hauweele <david@hauweele.net>
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

#ifndef _VERSION_H_
#define _VERSION_H_

#define _stringify(s) #s
#define stringify(s) _stringify(s)

#define PACKAGE "GPushD"
#define GPUSHD_AUTHOR  "David Hauweele"
#define GPUSHD_MAIL    "david@hauweele.net"
#define GPUSHD_WEBSITE "http://www.hauweele.net/~gawen/gpushd.html"
#define GPUSHD_LICENSE "BSD"

#define GPUSHD_MAJOR_VERSION    2
#define GPUSHD_MINOR_VERSION    2
#define GPUSHD_PROTOCOL_VERSION 3

#define VERSION stringify(GPUSHD_MAJOR_VERSION) "." stringify(GPUSHD_MINOR_VERSION)

#if defined(__FreeBSD__)
# define TARGET "FreeBSD"
#elif defined(__OpenBSD__)
# define TARGET "OpenBSD"
#elif defined(__NetBSD__)
# define TARGET "NetBSD"
#elif defined(__linux__)
# define TARGET "Linux"
#elif defined(__APPLE__)
# define TARGET "MacOS X"
#else
# define TARGET "unknown"
#endif /* TARGET */

#if !(defined COMMIT && defined PARTIAL_COMMIT)
# define PACKAGE_VERSION PACKAGE " v" VERSION
#else
# define PACKAGE_VERSION PACKAGE " v" VERSION " (commit: " PARTIAL_COMMIT ")"
#endif /* COMMIT */

void version(const char *target);

#ifdef COMMIT
void commit(void);
#endif /* COMMIT */

#endif /* _VERSION_H_ */
