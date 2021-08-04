//
// Created by Alexandros Hasikos on 22/07/2021.
//

#include "sign_commitment.h"

#include <pair_BN254.h>
#include <params.h>

void
sign_commitment(schemeD_signature *sig, ECP_BN254 *commitment, schemeD_secret_key *sk, csprng *prng) {
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

    ECP_BN254 a_times_x;

    ECP_BN254_copy(&a_times_x, &sig->a);
    PAIR_BN254_G1mul(&a_times_x, sk->x);

    BIG_256_56 alpha_xy;
    BIG_256_56_one(alpha_xy);

    BIG_256_56_modmul(alpha_xy, alpha, sk->x, MODULUS);
    BIG_256_56_modmul(alpha_xy, alpha_xy, sk->y, MODULUS);

    ECP_BN254 M_times_alpha_xy;

    ECP_BN254_copy(&M_times_alpha_xy, commitment);

    PAIR_BN254_G1mul(&M_times_alpha_xy, alpha_xy);

    ECP_BN254_copy(&sig->c, &M_times_alpha_xy);
    ECP_BN254_add(&sig->c, &a_times_x);
}