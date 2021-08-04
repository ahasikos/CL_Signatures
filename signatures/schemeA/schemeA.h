//
// Created by Alexandros Hasikos on 08/07/2021.
//

#ifndef CL_SIGNATURES_SCHEMEA_H
#define CL_SIGNATURES_SCHEMEA_H

#include <core.h>
#include <big_256_56.h>
#include <ecp_BN254.h>
#include <ecp2_BN254.h>

typedef struct {
    BIG_256_56 x;
    BIG_256_56 y;
} schemeA_sk;

typedef struct {
    ECP2_BN254 X;
    ECP2_BN254 Y;
} schemeA_pk;

typedef struct {
    ECP_BN254 a;
    ECP_BN254 b;
    ECP_BN254 c;
}schemeA_sig;

void schemeA_generate_sk(schemeA_sk *sk, csprng *prng);

void schemeA_generate_pk(schemeA_pk *pk, schemeA_sk *sk);

void schemeA_sign(schemeA_sig *sig, BIG_256_56 message, schemeA_sk *sk, csprng *prng);

int schemeA_verify(schemeA_sig *sig, BIG_256_56 message, schemeA_pk *pk);


#endif //CL_SIGNATURES_SCHEMEA_H
