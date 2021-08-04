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
} schemeB_secret_key;

typedef struct {
    ECP2_BN254 X;
    ECP2_BN254 Y;
    ECP2_BN254 Z;
    ECP2_BN254 g_2;
} schemeB_public_key;

typedef struct {
    ECP_BN254 a;
    ECP_BN254 A;
    ECP_BN254 b;
    ECP_BN254 B;
    ECP_BN254 c;
}schemeB_signature;

void schemeB_generate_sk(schemeB_secret_key *sk, csprng *prng);

void schemeB_generate_pk(schemeB_public_key *pk, schemeB_secret_key *sk);

void schemeB_sign(schemeB_signature *sig, BIG_256_56 message, BIG_256_56 randomness, schemeB_secret_key *sk, csprng *prng);

int schemeB_verify(schemeB_signature *sig, BIG_256_56 message, BIG_256_56 randomness, schemeB_public_key *pk);

#endif //CL_SIGNATURES_SCHEMEB_H
