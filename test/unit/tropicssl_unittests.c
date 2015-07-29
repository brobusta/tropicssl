/*
 *  SSL/TLS unit testing program
 *
 *  Based on XySSL: Copyright (C) 2006-2008  Christophe Devine
 *
 *  Copyright (C) 2009  Paul Bakker <polarssl_maintainer at polarssl dot org>
 *  Copyright (C) 2015  Vu Thanh Cong <vuthanhcong.ict@gmail.com>
 *
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the names of PolarSSL or XySSL nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 *  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "tropicssl_check.h"
#include "aes/check_aes.h"

#define DEBUG 1
#define TROPICSSL_UNITTESTS_NOFORK

#if DEBUG
#define _DBG(...)   printf(__VA_ARGS__)
#else
#define _DBG(...)
#endif

int main()
{
  int number_failed;
  SRunner *sr;
  size_t i;
  suite_getter_fn* suites[] = {
    aes_suite,
  };
  size_t num = sizeof(suites)/sizeof(void*);

  sr = srunner_create((suites[0])());
  for(i = 1; i < num; i++) {
    srunner_add_suite(sr, ((suite_getter_fn*)suites[i])());
  }

#ifdef TROPICSSL_UNITTESTS_NOFORK
  srunner_set_fork_status(sr, CK_NOFORK);
#endif
#ifdef TROPICSSL_UNITTESTS_FORK
  srunner_set_fork_status(sr, CK_FORK);
#endif

  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


