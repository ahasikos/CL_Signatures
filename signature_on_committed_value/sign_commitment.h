//
// Created by Alexandros Hasikos on 22/07/2021.
//

#ifndef CL_SIGNATURES_SIGN_COMMITMENT_H
#define CL_SIGNATURES_SIGN_COMMITMENT_H

#include <scheme_D/schemeD_signatures.h>

void sign_commitment(schemeD_signature *sig, octet *commitment, schemeD_secret_key *sk, csprng *prng);

#endif //CL_SIGNATURES_SIGN_COMMITMENT_H
