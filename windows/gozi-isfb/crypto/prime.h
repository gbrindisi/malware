/* PRIME.H - header file for PRIME.C
 */

/* Copyright (C) RSA Laboratories, a division of RSA Data Security,
     Inc., created 1991. All rights reserved.
 */

#include "global.h"
#include "rsaref.h"
#include "r_random.h"
#include "nn.h"

int GeneratePrime PROTO_LIST
  ((NN_DIGIT *, NN_DIGIT *, NN_DIGIT *, NN_DIGIT *, unsigned int,
    R_RANDOM_STRUCT *));
