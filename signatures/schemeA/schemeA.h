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
} schemeA_secret_key;

typedef struct {
    ECP2_BN254 X;
    ECP2_BN254 Y;
    ECP2_BN254 g_2;
} schemeA_public_key;

typedef struct {
    ECP_BN254 a;
    ECP_BN254 b;
    ECP_BN254 c;
}schemeA_signature;

void schemeA_generate_sk(schemeA_secret_key *sk, csprng *prng);

void schemeA_generate_pk(schemeA_public_key *pk, schemeA_secret_key *sk);

void schemeA_sign(schemeA_signature *sig, BIG_256_56 message, schemeA_secret_key *sk, csprng *prng);

int schemeA_verify(schemeA_signature *sig, BIG_256_56 message, schemeA_public_key *pk);


#endif //CL_SIGNATURES_SCHEMEA_H
