//
// Created by Alexandros Hasikos on 09/07/2021.
//

#ifndef CL_SIGNATURES_SCHEMEC_SIGNATURES_H
#define CL_SIGNATURES_SCHEMEC_SIGNATURES_H

#include <core.h>
#include <big_256_56.h>
#include <ecp2_BN254.h>
#include <ecp_BN254.h>

typedef struct {
    BIG_256_56 x_big;
    BIG_256_56 y_big;
    BIG_256_56 *z_big;
    uint32_t l;
} schemeC_secret_key;

typedef struct {
    ECP2_BN254 X;
    ECP2_BN254 Y;
    ECP2_BN254 *Z;
    uint32_t l;
    ECP2_BN254 g_2;
} schemeC_public_key;

typedef struct {
    ECP_BN254 a;
    ECP_BN254 *A;
    ECP_BN254 b;
    ECP_BN254 *B;
    ECP_BN254 c;
    uint32_t l;
}schemeC_signature;

void schemeC_init_secret_key(schemeC_secret_key *sk, BIG_256_56 *buf, uint32_t number_of_messages);

void schemeC_init_public_key(schemeC_public_key *pk, ECP2_BN254 *buf, uint32_t number_of_messages);

void schemeC_init_signature(schemeC_signature *sig, ECP_BN254 *buf_A, ECP_BN254 *buf_B, uint32_t number_of_messages);

void schemeC_generate_sk(schemeC_secret_key *sk, csprng *prng);

void schemeC_generate_pk(schemeC_public_key *pk, schemeC_secret_key *sk);

void schemeC_sign(schemeC_signature *sig, BIG_256_56 *message, schemeC_secret_key *sk, csprng *prng);

int schemeC_verify(schemeC_signature *sig, BIG_256_56 message, BIG_256_56 randomness, schemeC_public_key *pk);

#endif //CL_SIGNATURES_SCHEMEC_SIGNATURES_H
