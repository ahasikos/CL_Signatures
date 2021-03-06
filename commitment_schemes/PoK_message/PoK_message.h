//
// Created by Alexandros Hasikos on 21/07/2021.
//

#ifndef CL_SIGNATURES_POK_MESSAGE_H
#define CL_SIGNATURES_POK_MESSAGE_H

#include <big_256_56.h>
#include <ecp2_BN254.h>
#include <core.h>

#include <signatures/schemeD/schemeD.h>

void generate_commitment(ECP2_BN254 *commitment, BIG_256_56 *message, schemeD_pk *public_key);

void commitment_conversion(ECP_BN254 *commitment, schemeD_sk *sk, schemeD_sig *sig, BIG_256_56 *message);

void prover_1(ECP2_BN254 *T, BIG_256_56 *t, schemeD_pk *public_key, csprng *prng);

void prover_2(BIG_256_56 *s, BIG_256_56 c, BIG_256_56 *t, BIG_256_56 *message, uint32_t mlen);

int verifier(ECP2_BN254 *T, ECP2_BN254 *commitment, BIG_256_56 *s, BIG_256_56 c, schemeD_pk *public_key);

#endif //CL_SIGNATURES_POK_MESSAGE_H
