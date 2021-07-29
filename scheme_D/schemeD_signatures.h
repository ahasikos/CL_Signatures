//
// Created by Alexandros Hasikos on 22/07/2021.
//

#ifndef CL_SIGNATURES_SCHEMED_SIGNATURES_H
#define CL_SIGNATURES_SCHEMED_SIGNATURES_H

#include <core.h>
#include <big_256_56.h>
#include <ecp2_BN254.h>
#include <ecp_BN254.h>

typedef struct {
    BIG_256_56 x;
    BIG_256_56 y;
    BIG_256_56 *z;
    uint32_t l;
} schemeD_secret_key;

typedef struct {
    ECP2_BN254 X;
    ECP2_BN254 Y;
    ECP2_BN254 *Z;
    ECP2_BN254 *W;
    uint32_t l;
    ECP_BN254 g;
    ECP2_BN254 g_2;
} schemeD_public_key;

typedef struct {
    ECP_BN254 a;
    ECP_BN254 *A;
    ECP_BN254 b;
    ECP_BN254 *B;
    ECP_BN254 c;
    uint32_t l;
}schemeD_signature;

void schemeD_init_secret_key(schemeD_secret_key *sk, BIG_256_56 *buf, uint32_t number_of_messages);

void schemeD_init_public_key(schemeD_public_key *pk, ECP2_BN254 *Z_buf, ECP2_BN254 *W_buf, uint32_t number_of_messages);

void schemeD_init_signature(schemeD_signature *sig, ECP_BN254 *buf_A, ECP_BN254 *buf_B, uint32_t number_of_messages);

void schemeD_generate_sk(schemeD_secret_key *sk, csprng *prng);

void schemeD_generate_pk(schemeD_public_key *pk, schemeD_secret_key *sk);

void schemeD_sign(schemeD_signature *sig, BIG_256_56 *message, schemeD_secret_key *sk, csprng *prng);

int schemeD_verify(schemeD_signature *sig, BIG_256_56 *message, schemeD_public_key *pk);

#endif //CL_SIGNATURES_SCHEMED_SIGNATURES_H
