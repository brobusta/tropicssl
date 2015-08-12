/*
 *  X.509 test certificates
 *
 *  Based on XySSL: Copyright (C) 2006-2008  Christophe Devine
 *
 *  Copyright (C) 2009  Paul Bakker <polarssl_maintainer at polarssl dot org>
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

#include "tropicssl/config.h"

#if defined(TROPICSSL_CERTS)

const char test_ca_crt[] =
        "-----BEGIN CERTIFICATE-----\r\n"
        "MIIDrDCCApQCCQCMPWxl6p9WPzANBgkqhkiG9w0BAQUFADCBlzELMAkGA1UEBhMC\r\n"
        "Vk4xDjAMBgNVBAgMBUhhbm9pMQ4wDAYDVQQHDAVIYW5vaTETMBEGA1UECgwKQ2Fu\r\n"
        "aCBDYSBSbzERMA8GA1UECwwIRW1iZWRkZWQxFjAUBgNVBAMMDVZ1IFRoYW5oIENv\r\n"
        "bmcxKDAmBgkqhkiG9w0BCQEWGXZ1dGhhbmhjb25nLmljdEBnbWFpbC5jb20wHhcN\r\n"
        "MTUwODEyMDQzMjQ3WhcNMTYwODExMDQzMjQ3WjCBlzELMAkGA1UEBhMCVk4xDjAM\r\n"
        "BgNVBAgMBUhhbm9pMQ4wDAYDVQQHDAVIYW5vaTETMBEGA1UECgwKQ2FuaCBDYSBS\r\n"
        "bzERMA8GA1UECwwIRW1iZWRkZWQxFjAUBgNVBAMMDVZ1IFRoYW5oIENvbmcxKDAm\r\n"
        "BgkqhkiG9w0BCQEWGXZ1dGhhbmhjb25nLmljdEBnbWFpbC5jb20wggEiMA0GCSqG\r\n"
        "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCz1SyJglaT4E1pflniZ4eFwmENwa4PaNif\r\n"
        "67Vd/eYINaBeyazKV/4f4nV2GYzuaRMOGRGywsY1Vo8Lgut2EgmtevYn/uzxXIpr\r\n"
        "4i517goFMsCnDeEQKBWz1J0xaYWl2bxLfyZHisf3SIr4904nWXzKBhH2gmrGFcRc\r\n"
        "y1Z33ATclAYBQReU0I18GrgQ7bbgu+voh1VUJZl5hxLGDQlpSdJkY+QJDJSqYN8N\r\n"
        "X8zEdYiach0GBJxnfOMkum3rCTS4mdyHjwYtmVP27hPNI4rB7Fprx6pyBSVZsbqr\r\n"
        "FArenyg9EEEEv0Rb9tx5V1pUeW3TSRI/3CkK0vIo3iakpr12LckjAgMBAAEwDQYJ\r\n"
        "KoZIhvcNAQEFBQADggEBAHhqTcTJKcVELNlBkdErpZ/AOvxS5DdTUM6xZ1puHhFs\r\n"
        "KP7HiQEbH4h8gQW0KIaNE5RPhQNvlVrE8REsDymZIT3adKexZcIIpSWaZ5IiOqTb\r\n"
        "JNhigEw6RFdnKc1lcuN6xknIwOk8I6lVzc3BeSHoFqcoMJKEd/wStLPpApd177NU\r\n"
        "0YcCbW9pMKR13O61hIDtKztCTUhpMPXpcCy8jrj14XeY/33b+A83s1BXeJIjc4/U\r\n"
        "SHc2BdWs2hK2KqaLtYM6tUxG6n7RRMZVwNNBMYwXkCTa6GNhda+Rc+pysdwrwOQu\r\n"
        "HibH/eaHDK0qHXDIKmK9Ph7A+1mpwXCE98lk0D8Y/z8=\r\n"
        "-----END CERTIFICATE-----\r\n";

const char test_ca_key[] =
        "-----BEGIN RSA PRIVATE KEY-----\r\n"
        "Proc-Type: 4,ENCRYPTED\r\n"
        "DEK-Info: DES-EDE3-CBC,541D1BBE830D207A\r\n"
        "\r\n"
        "Rg0zT03HiTkLpk5WCybcrc9WxCOGM/tdcGPPX6Ost/JY1O1J44ltE0SjJyK8ta7U\r\n"
        "lrW4Zj6T4iko/2GZH/XeIvHDEPakURuBucaWqeIk/wgY7ua5VR+4n0/CPQit39ED\r\n"
        "lTw6yGer6JgZK7VxGygY6au2W/PwYorYp7mmd/E6nnZYqoy9YLGK87+K+Ljs4vJR\r\n"
        "j3EHP7ohkjEgSOuKcnRRQbSl4EpYf0R/Z5gSPXVkO9PINzUxvM0fxxPctFI6WKF7\r\n"
        "8CAeUQyVfllfdMlYH49iHKVzcU/DUEjvwp62VKLKLQvxXBndcq9lfPwi/NhybMDR\r\n"
        "mG7OYd0D1ln3i5I9//YIFaH5g2suHIOCF7eMLnDas74hOJ5vDAcFxuTtLV8s6X7T\r\n"
        "fSlt1UMWFd0ubwesw7ZaCHsNgMQfZdwmHAAznV8yCPRFrTHrZvvlJtXRtJ8YPEli\r\n"
        "+hcRtQkI92IgddBuA0wfrMJsz6s6j/DkP/+50+PBz4HbFyoE7w4Tku0+8TkOvaGP\r\n"
        "S1RnuSlMsx+Sq4YfxnLu29fPoyYig1NaIyCDWjD7u1PhkraYifzfEeTPVEcJlVz0\r\n"
        "8fRZfFCBZCNYLei6eNdgUUnMcMp8TnhQcxBhN2q3IBB6d0mYlMK3WcOR48CBGtqQ\r\n"
        "UoNX8bBEiyXgwdqDstVfVJJrjnp5A7t4CbGg+wM7MBdj59barjbcIKqNgRUiPElg\r\n"
        "U7POd9Axyi5LZ0lxcTmwBTADym3OvG7CVtzB04IuMuWIDcH+LG95qmudBAWKqj6f\r\n"
        "GxmuOPoJt9HPcyH5mHxh8ncKd3djo8EDTA6YwluwW49hVdPhlUdUjLOdgleztwJA\r\n"
        "Y3KgYUdK+L8EBAOEe56+LvtjEiR3/8tCCCmfasLpfZNIFt+F2Jo8Qw8FdGL+cH5K\r\n"
        "bsewucqJT/x2zGFLWktKFYm01xfj4DRXUD4sDb29AztXD8pBi0gKENjiAADCfeEP\r\n"
        "m44nGkbup1QDmEuv11AkbKc3101nbWiRXPhfVUhnzCixgiR/OJ0EnZM8uEozz9+y\r\n"
        "UvNZuzphDbvfPLiwDBNp/Yk4WuQvCIOVjykIZwripl+tbMywJxfG3R/TNJl2wIcm\r\n"
        "AmkmiFMnXzp2q9vG632PJUwnctkolImCSNvu+O66FG9sM/ZoMSKsN9jZbn8xidHA\r\n"
        "3E9XbiOw4TDCpR/yvxQPzqlg6mLRoklgZEqd7y7+QCBnOr6BH7ahhWUd1Azntvzf\r\n"
        "UG140DqxtOrSrFc/JBYpCZs+xdjLyVbGt9A3XZHqeCjm8g0ZYmIbWiQGpUyOtSAW\r\n"
        "HmnohFfqxJaJqzvh3hR5vSvezgnGg6em/AJVVITK1lOUYY0jMNIOrC1ZmlipM3cl\r\n"
        "LTeSISYBMk+MaGjY+71vWCOlnYRAUPyRdwIAGV+gShrcQYo6hdUx833ORFL4BFfk\r\n"
        "XPuR5XGpNBdP9O/ebcjLgX5kEdhi6dL29sXZ2Wbm8cXJTCfjUAE4IifndzpFKAiD\r\n"
        "M9YLXicrSq/P0xmmbCrSVcluroe/F5psBhgiFt1s/vr1k6lJC2sYhFwgj63Chmfq\r\n"
        "tTXWH1sW5E25kcu2lrLP8mKKgWOSjdS9m5gLYarNmd4V87t7fEfvZYVFcB75NVXc\r\n"
        "-----END RSA PRIVATE KEY-----\r\n";

const char test_ca_pwd[] = "tropicssl";

const char test_srv_crt[] =
        "-----BEGIN CERTIFICATE-----\r\n"
        "MIIDojCCAooCAQEwDQYJKoZIhvcNAQEFBQAwgZcxCzAJBgNVBAYTAlZOMQ4wDAYD\r\n"
        "VQQIDAVIYW5vaTEOMAwGA1UEBwwFSGFub2kxEzARBgNVBAoMCkNhbmggQ2EgUm8x\r\n"
        "ETAPBgNVBAsMCEVtYmVkZGVkMRYwFAYDVQQDDA1WdSBUaGFuaCBDb25nMSgwJgYJ\r\n"
        "KoZIhvcNAQkBFhl2dXRoYW5oY29uZy5pY3RAZ21haWwuY29tMB4XDTE1MDgxMjA0\r\n"
        "NDUwNVoXDTE2MDgxMTA0NDUwNVowgZUxCzAJBgNVBAYTAlZOMQ4wDAYDVQQIDAVI\r\n"
        "YW5vaTEOMAwGA1UEBwwFSGFub2kxEzARBgNVBAoMCkNhbmggQ2EgUm8xETAPBgNV\r\n"
        "BAsMCEVtYmVkZGVkMRQwEgYDVQQDDAtUZXN0IFNlcnZlcjEoMCYGCSqGSIb3DQEJ\r\n"
        "ARYZdnV0aGFuaGNvbmcuaWN0QGdtYWlsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\r\n"
        "ggEPADCCAQoCggEBAJys4Plyky9/eFQzmM8pICuWxt3GxeeAqiWfAHc7ToBUSK+j\r\n"
        "0t1Avjygn8UhYCO9Z3ydFMpyDeWAfHeZo2sg5ZgSvedZiUYkDHKPRaZQ7SukXI0z\r\n"
        "B9CQ2nWCQKeTNfOOoKDkVRTi1fBBBrxII7HUrahDmQVCPWBK+Uka1sgoMOGxDz/q\r\n"
        "CDNpyUgpVwPh1E5iDKc7Zn5eoxJMxK1gfbRwK3C+uu9819QjQq3CBcsrh7xE1fCY\r\n"
        "5PutvFXAU9NtbN7uyCyn798WNGW/puHL/0UoqeiYEeyHidVGEvVSwPk08Z74mDc8\r\n"
        "jiWjNSwtXc3C++KeuYZuMOQ3X8GYD5x4Jetg+QECAwEAATANBgkqhkiG9w0BAQUF\r\n"
        "AAOCAQEAQ0YSEYiN9Hhex4a0spUfUN+P2W8jKwcakTI+G6qx0IEugYWEg6nWeJ3r\r\n"
        "hGIsV5Z7dofwOJB2grfydYJ5Hyfg7BtmvvZhkewkBei+0Dmu6/r/sPVe2rr3YktT\r\n"
        "AVKFY1S5ayxsfshJDK8CHa+k/H6U2kWXYJpcj9W32iIR+LzraJ1Ni6yoTSePu93o\r\n"
        "0B9hBQX7eBIiPv5YPQGtQY6h5LY0Jr2rbODFiAPOkDXz8eDdqrkUZ+cH5XaDxiyH\r\n"
        "T7FS4Vp3raG5CB9l0mn+MqUlz9FhUyanGj9yNmF0PPM4hCxPZ3Lu1iKTYGuL5X1l\r\n"
        "szfTx2kch1hoBw2afk/3lTyavSMT4A==\r\n"
        "-----END CERTIFICATE-----\r\n";

const char test_srv_key[] =
        "-----BEGIN RSA PRIVATE KEY-----\r\n"
        "MIIEpAIBAAKCAQEAnKzg+XKTL394VDOYzykgK5bG3cbF54CqJZ8AdztOgFRIr6PS\r\n"
        "3UC+PKCfxSFgI71nfJ0UynIN5YB8d5mjayDlmBK951mJRiQMco9FplDtK6RcjTMH\r\n"
        "0JDadYJAp5M1846goORVFOLV8EEGvEgjsdStqEOZBUI9YEr5SRrWyCgw4bEPP+oI\r\n"
        "M2nJSClXA+HUTmIMpztmfl6jEkzErWB9tHArcL6673zX1CNCrcIFyyuHvETV8Jjk\r\n"
        "+628VcBT021s3u7ILKfv3xY0Zb+m4cv/RSip6JgR7IeJ1UYS9VLA+TTxnviYNzyO\r\n"
        "JaM1LC1dzcL74p65hm4w5DdfwZgPnHgl62D5AQIDAQABAoIBAQCT4Bf3WMzS590K\r\n"
        "nCh+XrKecZEBgbsI5cex+oDWCIPvW52/KUC80366emBSD05ObVZfp2MYMM4s7ziL\r\n"
        "Kde0JTiOcCINWdTW/u9AsTlr4LX5mwg/vQqDMDUA9A9SGv+xAc1aDii/rdl/CeDx\r\n"
        "lKUcE0BUsHidHggP+rOO7GYMROLeIGXEBChyEKnXFeDhX0uZ9HP0CfxvzZIEdpXf\r\n"
        "9DXCcz8HqlXv5+RpnWH8g4t2qKWFHPyo+6r1EMOk+HBZqrSRiS006NT3J9+bltJ1\r\n"
        "IixnD2yKw2KEC+/2hiLFFfqEIWC6ttaDy0Gjrr9GaFYFx99IlzCSjPbvyUpWnIzR\r\n"
        "LxjpBGABAoGBAMxDMuQg/4KmMhWsKSl4OgI9GVAMTlbtkcILrONEA85SpppwV3kn\r\n"
        "6xs7FKYiXUZ9GgXQQ7EPllamA0ICwTXwF9IJ7w+rCPzuF9U9iB5PfQs0scKyBbGs\r\n"
        "aYgCC0Y96U7agpFTD0iFL7e95ynsef+zXVKK/jfQvdWBN7CtraGw6mfRAoGBAMRc\r\n"
        "B1iOq1G5rFRROzI296TM8Hz6Ksb4VCFlZrM+UzHU81HJc7AuZaoORHNqnBPDl+71\r\n"
        "lmlbfQGbXAmpXAgQ4p8AEKPx2K10QHXQR/pZaZXagVZ7V2HARwyxF0YtvNlY9RhD\r\n"
        "Qk6SFIVKFmhmILQSKKo4PGp0jMSGJFzjru2MUfoxAoGANgXLzuQfT7mO44Z9+HbQ\r\n"
        "uMjaCf7HNVxtwWl/Fzhk3UukvpHZwLRbDP+qLWpHSx5JJKJ5VLnvpAkSMYIzAYX3\r\n"
        "dtijvnwYy3RZH0+/0WxqgO012m1k7iHQY2VPAAvdybom8DKMhzyaazkxizf86DDT\r\n"
        "DMKwC6kMnAwp43N7yZjV1hECgYEAj7/3uMMpdHkDSe718TsAbOuDm1rheixOGuzL\r\n"
        "FKmp6i9FujhKs04kKyyqu/vuKyHj1pJ//L13dHeyF3ie4WDLJy+6/uqMf989WYKT\r\n"
        "TxmqDIScbx14yR0kZow2x6+wM0XGmG6U2kRjNXkZknBBvNIWZxcoU57jdvPlJwOg\r\n"
        "ClPRp+ECgYBqAtGDmmoSpEvASiKRo9/L1HRzkqpuAneL0OXk5mGBPqBWDNP+KzkJ\r\n"
        "mpRfGsfS9izcVH6CqhdzhqF97l0/yVOpRhZns5k4329/4HeUDZDukWK7BrMwNzil\r\n"
        "PbLgsF6UzLGVKUPPscqrN0CxLmcFH+qR1K0I+uIDxY4vK5IE5XWyeA==\r\n"
        "-----END RSA PRIVATE KEY-----\r\n";

const char test_cli_crt[] =
        "-----BEGIN CERTIFICATE-----\r\n"
        "MIIDojCCAooCAQEwDQYJKoZIhvcNAQEFBQAwgZcxCzAJBgNVBAYTAlZOMQ4wDAYD\r\n"
        "VQQIDAVIYW5vaTEOMAwGA1UEBwwFSGFub2kxEzARBgNVBAoMCkNhbmggQ2EgUm8x\r\n"
        "ETAPBgNVBAsMCEVtYmVkZGVkMRYwFAYDVQQDDA1WdSBUaGFuaCBDb25nMSgwJgYJ\r\n"
        "KoZIhvcNAQkBFhl2dXRoYW5oY29uZy5pY3RAZ21haWwuY29tMB4XDTE1MDgxMjA0\r\n"
        "MzMyMVoXDTE2MDgxMTA0MzMyMVowgZUxCzAJBgNVBAYTAlZOMQ4wDAYDVQQIDAVI\r\n"
        "YW5vaTEOMAwGA1UEBwwFSGFub2kxEzARBgNVBAoMCkNhbmggQ2EgUm8xETAPBgNV\r\n"
        "BAsMCEVtYmVkZGVkMRQwEgYDVQQDDAtUZXN0IENsaWVudDEoMCYGCSqGSIb3DQEJ\r\n"
        "ARYZdnV0aGFuaGNvbmcuaWN0QGdtYWlsLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\r\n"
        "ggEPADCCAQoCggEBALxVjrgmpMSRFDw4bweyQtvEn3BBfWhzJBroOIERnhF6hAb7\r\n"
        "3zGtajuRH3luhRx7qrq2+4DOD771rROJLc7L4tKdVwUFOZwlpBcoeOmzg+i8OPUF\r\n"
        "FKO40kYUvJJmo8lZ8jxCJVZhJC/mHp7RlAAqsWBx3zGGxggxUu0cvncO2xal+HI8\r\n"
        "EsCwzPJ8fK99hc831Z/15IJinAV33oLPTKzNDHBCIE7nuvaLfqWdx0wMTBhoTMaU\r\n"
        "Ht/d4ECusdjvVWcjh1dS644tYn2BfLPuN9ONBuHB63pnG0Ql7HI8dNHVurfghwRl\r\n"
        "5FGI+8cRfiLjNICy5iQQL6F0NDrkoBgxbedhIAkCAwEAATANBgkqhkiG9w0BAQUF\r\n"
        "AAOCAQEALCsEoaEDMdRit+dvwVup8FEI2dKy5Udy8CNeGAPT/dXmGD8UAV7unv1m\r\n"
        "JJBD+icEwHRCM3JXFFSGrlo8OeqviVXwdubjrYYidayg+jkP7B7bUyK1az5xstUh\r\n"
        "vRuhA1W4OIOhgjg0/TXgsiUpW8DZSLzRjYw0Vo1QDieD1gjRneekq/hbpnMb+qSQ\r\n"
        "tfZ4P3cfjTuZMr0j0rc2XGLbYtQP+tnSesXVTWpGmUw6veXVGyQoRdnrZk1Z3+Wq\r\n"
        "wRkMaGNlDSjbNjGw8WX8BsxxSTtX2yk/z5KgUc7lkjrPLpwC+RfssUHZurBCtkLD\r\n"
        "niKyDFlqaK2XzBz0fjMBj2mFRfB26w==\r\n"
        "-----END CERTIFICATE-----\r\n";

const char test_cli_key[] =
        "-----BEGIN RSA PRIVATE KEY-----\r\n"
        "MIIEpAIBAAKCAQEAvFWOuCakxJEUPDhvB7JC28SfcEF9aHMkGug4gRGeEXqEBvvf\r\n"
        "Ma1qO5EfeW6FHHuqurb7gM4PvvWtE4ktzsvi0p1XBQU5nCWkFyh46bOD6Lw49QUU\r\n"
        "o7jSRhS8kmajyVnyPEIlVmEkL+YentGUACqxYHHfMYbGCDFS7Ry+dw7bFqX4cjwS\r\n"
        "wLDM8nx8r32FzzfVn/XkgmKcBXfegs9MrM0McEIgTue69ot+pZ3HTAxMGGhMxpQe\r\n"
        "393gQK6x2O9VZyOHV1Lrji1ifYF8s+43040G4cHremcbRCXscjx00dW6t+CHBGXk\r\n"
        "UYj7xxF+IuM0gLLmJBAvoXQ0OuSgGDFt52EgCQIDAQABAoIBADb1rMl2lXy7bbFJ\r\n"
        "MrWHQtWJYpHKusMhXrbvb5XSw1MMcrzrAa4okijB5/Jy2yt9t0v3nBtxhszOOuzJ\r\n"
        "inGftBiMS9muNaqonWMYr3hbp7HiQ6jVC7nfdJV49bKvezqGIheNogG8JWhI+kSU\r\n"
        "mmEWFF81u9FjKCU5555EVhy+XBcWZaiQUyHY++rafqv62L9Iu6HtUMs2cLJEauKi\r\n"
        "N9hlFKfWNXuthLBuVSkHmgnJYJrP1r0VNp16lBVDSxPkeB5IHiGcVBT4Dyo4kYc1\r\n"
        "oyjJ4XyfXtjd6u7cTQEmo1HxtJM5N27ZW8NCNs+Zc5LcyRS/YoSFT7U65K+eYIVp\r\n"
        "pia9rQECgYEA6hBvljPlwEExZ0/UUluNzEaMVEpJSKzgHKCXv1vASZhjmQXFDaxW\r\n"
        "NWZ8223MlTeiEv4nNOrlFaDkIhDTBpTeUVqNSaXCpRMIVdtjsAfF88LR/dKH34d6\r\n"
        "nutdS3/y4s9TZ84Mz44XdigE9evC5gF4yyiNtDS0lXuLhLEkxtxwG6ECgYEAzfv8\r\n"
        "63X+8uMixbkOevFSbcJlf3QJXwJEdOON3pX8ngwaDM8LkYPwpm60S8+jvWhdXmgy\r\n"
        "ZWBgHvgXVkZKHQRNekjSrJXrYyclq0Jn4i7zf3UTWpJFUJTUlf2Uh79kvm+/soiX\r\n"
        "jpdTIrsWm/EIxoTKBifbybXFvQuveB05tt9p62kCgYBLxNxKdCxYiwISHn5t1qNV\r\n"
        "UDUXCCEm/Idj3PyifnIFoOYE4CBE59fUW4PpiGakmyjFGy7X634S/U08VdPqGoDJ\r\n"
        "NxXrlFQpGbsmB+oCTtHesd9GWkOPsYyZKzm9OgMHNvQZ81KkUav4nMXWUeZ6jFls\r\n"
        "8ojEoBchGKg2YR21niBQYQKBgQCIgszOm4eYHrHHyenvzojrVt7/Rb6EKbOGp9w4\r\n"
        "vLwLXkfRX1HyYTeWhV2VtIl2mHjwfSuRBfsN6ytEMRci/dv/A84jNMQoFSSgyESi\r\n"
        "oK0dNlDaQIARdGEi+kh6Ynx4vQSVZHLUvDMLnGPSez5umkhtJfNCTeY7cEgc2XmL\r\n"
        "WasPqQKBgQDHFsYeEDhvloqenEm/lh1D9ck2GlzQF16xj/wkGnDkt8vQI+hn+fvr\r\n"
        "Jd7hlqZTxxSOIyr7I6+lKgz/oMAJMBVkcPwsXqha9ukAAnsPP5FsdJGP4f7JhG8C\r\n"
        "swiP8rLb269fx7Q2y0VZltiDOROOqgqwDAhGNsgfoNrUoPyt8ao9Bg==\r\n"
        "-----END RSA PRIVATE KEY-----\r\n";

#endif
