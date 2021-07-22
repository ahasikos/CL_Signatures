//
// Created by Alexandros Hasikos on 22/07/2021.
//

#ifndef CL_SIGNATURES_SIGN_COMMITMENT_H
#define CL_SIGNATURES_SIGN_COMMITMENT_H

#include <scheme_C/schemeC_signatures.h>

void sign_commitment(schemeC_signature *sig, ECP2_BN254 *commitment, schemeC_secret_key *sk, csprng *prng);

#endif //CL_SIGNATURES_SIGN_COMMITMENT_H
