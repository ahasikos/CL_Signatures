//
// Created by Alexandros Hasikos on 09/07/2021.
//

#ifndef CL_SIGNATURES_SCHEMEB_H
#define CL_SIGNATURES_SCHEMEB_H

#include <core.h>
#include <big_256_56.h>
#include <ecp2_BN254.h>
#include <ecp_BN254.h>

typedef struct {
    BIG_256_56 x;
    BIG_256_56 y;
    BIG_256_56 z;
} schemeB_sk;

typedef struct {
    ECP2_BN254 X;
    ECP2_BN254 Y;
    ECP2_BN254 Z;
} schemeB_pk;

typedef struct {
    ECP_BN254 a;
    ECP_BN254 A;
    ECP_BN254 b;
    ECP_BN254 B;
    ECP_BN254 c;
}schemeB_sig;

void schemeB_generate_sk(schemeB_sk *sk, csprng *prng);

void schemeB_generate_pk(schemeB_pk *pk, schemeB_sk *sk);

void schemeB_sign(schemeB_sig *sig, BIG_256_56 message, BIG_256_56 randomness, schemeB_sk *sk, csprng *prng);

int schemeB_verify(schemeB_sig *sig, BIG_256_56 message, BIG_256_56 randomness, schemeB_pk *pk);

#endif //CL_SIGNATURES_SCHEMEB_H
