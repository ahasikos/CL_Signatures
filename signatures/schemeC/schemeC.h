//
// Created by Alexandros Hasikos on 09/07/2021.
//

#ifndef CL_SIGNATURES_SCHEMEC_H
#define CL_SIGNATURES_SCHEMEC_H

#include <core.h>
#include <big_256_56.h>
#include <ecp2_BN254.h>
#include <ecp_BN254.h>

typedef struct {
    BIG_256_56 x;
    BIG_256_56 y;
    BIG_256_56 *z;
    uint32_t l;
} schemeC_sk;

typedef struct {
    ECP2_BN254 X;
    ECP2_BN254 Y;
    ECP2_BN254 *Z;
    uint32_t l;
} schemeC_pk;

typedef struct {
    ECP_BN254 a;
    ECP_BN254 *A;
    ECP_BN254 b;
    ECP_BN254 *B;
    ECP_BN254 c;
    uint32_t l;
}schemeC_sig;

void schemeC_init_keypair(schemeC_sk* sk, schemeC_pk *pk, uint32_t number_of_messages);

void schemeC_destroy_keypair(schemeC_sk* sk, schemeC_pk *pk);

void schemeC_init_signature(schemeC_sig *sig, uint32_t number_of_messages);

void schemeC_destroy_signature(schemeC_sig *sk);

void schemeC_generate_sk(schemeC_sk *sk, csprng *prng);

void schemeC_generate_pk(schemeC_pk *pk, schemeC_sk *sk);

void schemeC_sign(schemeC_sig *sig, BIG_256_56 *message, schemeC_sk *sk, csprng *prng);

int schemeC_verify(schemeC_sig *sig, BIG_256_56 *message, schemeC_pk *pk);

#endif //CL_SIGNATURES_SCHEMEC_H
