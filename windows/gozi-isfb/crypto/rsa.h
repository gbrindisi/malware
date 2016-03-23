/* RSA.H - header file for RSA.C
 */

/* Copyright (C) RSA Laboratories, a division of RSA Data Security,
     Inc., created 1991. All rights reserved.
 */

#include "nn.h"
#include "global.h"
#include "rsaref.h"
#include "r_random.h"

int RSAPublicEncrypt PROTO_LIST 
  ((unsigned char *, unsigned int *, unsigned char *, unsigned int,
    R_RSA_PUBLIC_KEY *, R_RANDOM_STRUCT *));
int RSAPrivateEncrypt PROTO_LIST
  ((unsigned char *, unsigned int *, unsigned char *, unsigned int,
    R_RSA_PRIVATE_KEY *));
int RSAPublicDecrypt PROTO_LIST 
  ((unsigned char *, unsigned int *, unsigned char *, unsigned int,
    R_RSA_PUBLIC_KEY *));
int RSAPrivateDecrypt PROTO_LIST
  ((unsigned char *, unsigned int *, unsigned char *, unsigned int,
    R_RSA_PRIVATE_KEY *));
