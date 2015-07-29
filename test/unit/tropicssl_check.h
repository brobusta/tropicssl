/*
 *  SSL/TLS unit testing header
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


#ifndef TEST_UNIT_TROPICSSL_CHECK_H_
#define TEST_UNIT_TROPICSSL_CHECK_H_

#include <check.h>
#include <stdlib.h>

#define FAIL_RET() do { fail(); return; } while(0)
#define EXPECT(x) fail_unless(x)
#define EXPECT_RET(x) do { fail_unless(x); if(!(x)) { return; }} while(0)
#define EXPECT_RETX(x, y) do { fail_unless(x); if(!(x)) { return y; }} while(0)
#define EXPECT_RETNULL(x) EXPECT_RETX(x, NULL)

typedef struct {
    TFun func;
    const char *name;
} testfunc;

#define TESTFUNC(x) {(x), "" # x "" }

/* Modified function from check.h, supplying function name */
#define tcase_add_named_test(tc,tf) \
   _tcase_add_test((tc),(tf).func,(tf).name,0, 0, 0, 1)

/** typedef for a function returning a test suite */
typedef Suite* (suite_getter_fn)(void);

/** Create a test suite */
static Suite* create_suite(const char* name, testfunc *tests, size_t num_tests, SFun setup, SFun teardown)
{
  size_t i;
  Suite *s = suite_create(name);

  for(i = 0; i < num_tests; i++) {
    TCase *tc_core = tcase_create(name);
    if ((setup != NULL) || (teardown != NULL)) {
      tcase_add_checked_fixture(tc_core, setup, teardown);
    }
    tcase_add_named_test(tc_core, tests[i]);
    suite_add_tcase(s, tc_core);
  }
  return s;
}

#endif /* TEST_UNIT_TROPICSSL_CHECK_H_ */
