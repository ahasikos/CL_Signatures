//
// Created by Alexandros Hasikos on 22/07/2021.
//

#ifndef CL_SIGNATURES_SIGN_COMMITMENT_H
#define CL_SIGNATURES_SIGN_COMMITMENT_H

#include <signatures/schemeD/schemeD.h>

void sign_commitment(schemeD_signature *sig, ECP_BN254 *commitment, schemeD_secret_key *sk, csprng *prng);

#endif //CL_SIGNATURES_SIGN_COMMITMENT_H
