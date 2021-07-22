//
// Created by Alexandros Hasikos on 22/07/2021.
//

#include "sign_commitment.h"

#include <pair_BN254.h>

void sign_commitment(schemeC_signature *sig, ECP2_BN254 *commitment, schemeC_secret_key *sk, csprng *prng) {
    BIG_256_56 alpha;
    BIG_256_56_random(alpha, prng);

    ECP_BN254_generator(&sig->a);
    PAIR_BN254_G1mul(&sig->a, alpha);

    for(int i = 0; i < sk->l; i++) {
        ECP_BN254_copy(&sig->A[i], &sig->a);
        PAIR_BN254_G1mul(&sig->A[i], sk->z[i]);

        ECP_BN254_copy(&sig->B[i], &sig->A[i]);
        PAIR_BN254_G1mul(&sig->B[i], sk->y);
    }

    ECP_BN254_copy(&sig->b, &sig->a);
    PAIR_BN254_G1mul(&sig->b, sk->y);
}