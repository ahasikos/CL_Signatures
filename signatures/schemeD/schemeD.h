//
// Created by Alexandros Hasikos on 22/07/2021.
//

#ifndef CL_SIGNATURES_SCHEMED_H
#define CL_SIGNATURES_SCHEMED_H

#include <core.h>
#include <big_256_56.h>
#include <ecp2_BN254.h>
#include <ecp_BN254.h>

typedef struct {
    BIG_256_56 x;
    BIG_256_56 y;
    BIG_256_56 *z;
    uint32_t l;
} schemeD_sk;

typedef struct {
    ECP2_BN254 X;
    ECP2_BN254 Y;
    ECP2_BN254 *Z;
    ECP2_BN254 *W;
    uint32_t l;
    ECP_BN254 g;
    ECP2_BN254 g_2;
} schemeD_pk;

typedef struct {
    ECP_BN254 a;
    ECP_BN254 *A;
    ECP_BN254 b;
    ECP_BN254 *B;
    ECP_BN254 c;
    uint32_t l;
}schemeD_sig;

void schemeD_init_keypair(schemeD_sk* sk, schemeD_pk *pk, uint32_t number_of_messages);

void schemeD_destroy_keypair(schemeD_sk* sk, schemeD_pk *pk);

void schemeD_init_signature(schemeD_sig *sig, uint32_t number_of_messages);

void schemeD_destroy_signature(schemeD_sig *sig);

void schemeD_generate_sk(schemeD_sk *sk, csprng *prng);

void schemeD_generate_pk(schemeD_pk *pk, schemeD_sk *sk);

void schemeD_sign(schemeD_sig *sig, BIG_256_56 *message, schemeD_sk *sk, csprng *prng);

int schemeD_verify(schemeD_sig *sig, BIG_256_56 *message, schemeD_pk *pk);

#endif //CL_SIGNATURES_SCHEMED_H
