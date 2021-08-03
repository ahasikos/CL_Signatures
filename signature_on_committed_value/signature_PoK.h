//
// Created by Alexandros Hasikos on 22/07/2021.
//

#ifndef CL_SIGNATURES_SIGNATURE_POK_H
#define CL_SIGNATURES_SIGNATURE_POK_H

#include <scheme_D/schemeD_signatures.h>

#include <fp12_BN254.h>

typedef struct {
    BIG_256_56 r;
} PoK_proof;

void PoK_compute_blind_signature(schemeD_signature *blind_sig, schemeD_signature *sig, PoK_proof *proof, csprng *prng);

void PoK_generate_commitment(FP12_BN254 *commitment, PoK_proof *proof, BIG_256_56 *message, schemeD_public_key *pk,
                             schemeD_signature *blind_sig);

void
PoK_prover_1(FP12_BN254 *T, BIG_256_56 t1, BIG_256_56 *t2, schemeD_public_key *public_key, schemeD_signature *blind_sig,
             csprng *prng);

void PoK_prover_2(BIG_256_56 s1, BIG_256_56 *s2, BIG_256_56 c, BIG_256_56 t1, BIG_256_56 *t2, BIG_256_56 *message,
                  PoK_proof *proof, schemeD_signature *sig);

int PoK_verifier(BIG_256_56 s1, BIG_256_56 *s2, BIG_256_56 c, FP12_BN254 *T, FP12_BN254 *commitment,
                 schemeD_public_key *public_key, schemeD_signature *blind_sig);

#endif //CL_SIGNATURES_SIGNATURE_POK_H
