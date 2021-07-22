//
// Created by Alexandros Hasikos on 22/07/2021.
//

#ifndef CL_SIGNATURES_SIGNATURE_POK_H
#define CL_SIGNATURES_SIGNATURE_POK_H

#include <scheme_D/schemeD_signatures.h>

#include <fp12_BN254.h>

void PoK_compute_blind_signature(schemeD_signature *blind_sig, schemeD_signature *sig, csprng *prng);

void PoK_generate_commitment(FP12_BN254 *commitment, schemeD_signature *blind_sig);

void
PoK_prover_1(ECP2_BN254 *T, BIG_256_56 *t1, BIG_256_56 t2, BIG_256_56 *message, schemeD_public_key *public_key,
             schemeD_signature *blind_sig, csprng *prng);

#endif //CL_SIGNATURES_SIGNATURE_POK_H
