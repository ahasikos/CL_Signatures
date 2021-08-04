//
// Created by Alexandros Hasikos on 21/07/2021.
//

#ifndef CL_SIGNATURES_COMMITMENT_SCHEME_H
#define CL_SIGNATURES_COMMITMENT_SCHEME_H

#include <big_256_56.h>
#include <ecp2_BN254.h>
#include <core.h>

#include <scheme_D/schemeD_signatures.h>

void generate_commitment(ECP2_BN254 *commitment, BIG_256_56 *message, schemeD_public_key *public_key);

void commitment_conversion(ECP_BN254 *commitment, schemeD_secret_key *sk, schemeD_signature *sig, BIG_256_56 *message);

void prover_1(ECP2_BN254 *T, BIG_256_56 *t, schemeD_public_key *public_key, csprng *prng);

void prover_2(BIG_256_56 *s, BIG_256_56 c, BIG_256_56 *t, BIG_256_56 *message, uint32_t mlen);

int verifier(ECP2_BN254 *T, ECP2_BN254 *commitment, BIG_256_56 *s, BIG_256_56 c, schemeD_public_key *public_key);

#endif //CL_SIGNATURES_COMMITMENT_SCHEME_H
