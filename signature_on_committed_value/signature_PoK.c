//
// Created by Alexandros Hasikos on 22/07/2021.
//

#include "signature_PoK.h"

#include <pair_BN254.h>

void PoK_compute_blind_signature(schemeD_signature *blind_sig, schemeD_signature *sig, csprng *prng) {
    BIG_256_56 r_prime;
    BIG_256_56_random(blind_sig->r, prng);
    BIG_256_56_random(r_prime, prng);

    ECP_BN254_copy(&blind_sig->a, &sig->a);
    PAIR_BN254_G1mul(&blind_sig->a, blind_sig->r);

    ECP_BN254_copy(&blind_sig->b, &sig->b);
    PAIR_BN254_G1mul(&blind_sig->b, blind_sig->r);

    ECP_BN254_copy(&blind_sig->c, &sig->c);
    PAIR_BN254_G1mul(&blind_sig->c, blind_sig->r);

    PAIR_BN254_G1mul(&blind_sig->c, r_prime);

    for(int i = 0; i < sig->l; i++) {
        ECP_BN254_copy(&blind_sig->A[i], &sig->A[i]);
        PAIR_BN254_G1mul(&blind_sig->A[i], blind_sig->r);

        ECP_BN254_copy(&blind_sig->B[i], &sig->B[i]);
        PAIR_BN254_G1mul(&blind_sig->B[i], blind_sig->r);
    }
}

void PoK_generate_commitment(FP12_BN254 *commitment, schemeD_signature *blind_sig) {

    ECP2_BN254 g;

    ECP2_BN254_generator(&g);
    PAIR_BN254_G2mul(&g, blind_sig->r);

    PAIR_BN254_ate(commitment, &g, &blind_sig->c);
    PAIR_BN254_fexp(commitment);
}

void PoK_prover_1(ECP2_BN254 *T, BIG_256_56 *t1, BIG_256_56 t2, BIG_256_56 *message, schemeD_public_key *public_key,
                  schemeD_signature *blind_sig, csprng *prng) {
    //Generate t1 and t2
    for(int i = 0; i < public_key->l; i++) {
        BIG_256_56_random(t1[i], prng);
    }

    BIG_256_56_random(t2, prng);

    FP12_BN254 Vx, Vxy, Vxy_i, prod, Vx_times_Vxy;
    ECP_BN254 B_times_m_i;
    FP12_BN254_one(&prod);

    PAIR_BN254_ate(&Vx, &public_key->X, &blind_sig->a);
    PAIR_BN254_fexp(&Vx);

    PAIR_BN254_G1mul(&blind_sig->b, message[0]);
    PAIR_BN254_G1mul(&blind_sig->b, t1[0]);
    PAIR_BN254_ate(&Vxy, &public_key->X, &blind_sig->b);
    PAIR_BN254_fexp(&Vxy);

    FP12_BN254_copy(&Vx_times_Vxy, &Vx);
    FP12_BN254_mul(&Vx_times_Vxy, &Vxy);

    for(int i = 0; i < public_key->l; i++) {
        ECP_BN254_copy(&B_times_m_i, &blind_sig->B[i]);
        PAIR_BN254_G1mul(&B_times_m_i, message[i]);
        PAIR_BN254_G1mul(&B_times_m_i, t1[i]);

        PAIR_BN254_ate(&Vxy_i, &public_key->X, &B_times_m_i);
        PAIR_BN254_fexp(&Vxy_i);

        FP12_BN254_mul(&prod, &Vxy_i);
    }




}
