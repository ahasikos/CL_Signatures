//
// Created by Alexandros Hasikos on 22/07/2021.
//

#include "signature_PoK.h"
#include "params.h"

#include <pair_BN254.h>
#include <utils/utils.h>

void PoK_compute_blind_signature(schemeD_signature *blind_sig, schemeD_signature *sig, PoK_proof *proof, csprng *prng) {
    BIG_256_56 r_prime;
    BIG_256_56_random(r_prime, prng);

    ECP_BN254_copy(&blind_sig->a, &sig->a);
    PAIR_BN254_G1mul(&blind_sig->a, proof->r);

    ECP_BN254_copy(&blind_sig->b, &sig->b);
    PAIR_BN254_G1mul(&blind_sig->b, proof->r);

    ECP_BN254_copy(&blind_sig->c, &sig->c);
    PAIR_BN254_G1mul(&blind_sig->c, proof->r);

    PAIR_BN254_G1mul(&blind_sig->c, r_prime);

    for(int i = 0; i < sig->l; i++) {
        ECP_BN254_copy(&blind_sig->A[i], &sig->A[i]);
        PAIR_BN254_G1mul(&blind_sig->A[i], proof->r);

        ECP_BN254_copy(&blind_sig->B[i], &sig->B[i]);
        PAIR_BN254_G1mul(&blind_sig->B[i], proof->r);
    }
}

void PoK_generate_commitment(FP12_BN254 *commitment, PoK_proof *proof, BIG_256_56 *message, schemeD_public_key *pk,
                             schemeD_signature *blind_sig) {

    FP12_BN254 Vx, Vxy, Vxy_i, prod;
    ECP_BN254 B_times_m_i, b_blind, a_blind;

    FP12_BN254_one(commitment);
    FP12_BN254_one(&prod);

    ECP_BN254_copy(&a_blind, &blind_sig->a);
    PAIR_BN254_G1mul(&a_blind, proof->r);
    PAIR_BN254_ate(&Vx, &pk->X, &a_blind);
    PAIR_BN254_fexp(&Vx);

    ECP_BN254_copy(&b_blind, &blind_sig->b);
    PAIR_BN254_G1mul(&b_blind, message[0]);
    PAIR_BN254_ate(&Vxy, &pk->X, &b_blind);
    PAIR_BN254_fexp(&Vxy);

    for(int i = 1; i < pk->l; i++) {
        ECP_BN254_copy(&B_times_m_i, &blind_sig->B[i]);
        PAIR_BN254_G1mul(&B_times_m_i, message[i]);

        PAIR_BN254_ate(&Vxy_i, &pk->X, &B_times_m_i);
        PAIR_BN254_fexp(&Vxy_i);

        FP12_BN254_mul(&prod, &Vxy_i);
    }

    FP12_BN254_mul(commitment, &Vx);
    FP12_BN254_mul(commitment, &Vxy);
    FP12_BN254_mul(commitment, &prod);
}

void
PoK_prover_1(FP12_BN254 *T, BIG_256_56 t1, BIG_256_56 *t2, schemeD_public_key *public_key, schemeD_signature *blind_sig,
             csprng *prng) {

    FP12_BN254_one(T);

    //Generate t1 and t2
    BIG_256_56_random(t1, prng);

    for(int i = 0; i < public_key->l; i++) {
        BIG_256_56_random(t2[i], prng);
    }

    FP12_BN254 Vx, Vxy, Vxy_i, prod;
    ECP_BN254 B_times_m_i, b_blind, a_blind;

    FP12_BN254_one(&prod);

    ECP_BN254_copy(&a_blind, &blind_sig->a);
    PAIR_BN254_G1mul(&a_blind, t1);
    PAIR_BN254_ate(&Vx, &public_key->X, &a_blind);
    PAIR_BN254_fexp(&Vx);

    ECP_BN254_copy(&b_blind, &blind_sig->b);
    PAIR_BN254_G1mul(&b_blind, t2[0]);
    PAIR_BN254_ate(&Vxy, &public_key->X, &b_blind);
    PAIR_BN254_fexp(&Vxy);

    for(int i = 1; i < public_key->l; i++) {
        ECP_BN254_copy(&B_times_m_i, &blind_sig->B[i]);
        PAIR_BN254_G1mul(&B_times_m_i, t2[i]);

        PAIR_BN254_ate(&Vxy_i, &public_key->X, &B_times_m_i);
        PAIR_BN254_fexp(&Vxy_i);

        FP12_BN254_mul(&prod, &Vxy_i);
    }

    FP12_BN254_mul(T, &Vx);
    FP12_BN254_mul(T, &Vxy);
    FP12_BN254_mul(T, &prod);
}

void PoK_prover_2(BIG_256_56 s1, BIG_256_56 *s2, BIG_256_56 c, BIG_256_56 t1, BIG_256_56 *t2, BIG_256_56 *message,
                  PoK_proof *proof, schemeD_signature *sig) {

    BIG_256_56 tmp;

    BIG_256_56_modmul(tmp, proof->r, c, MODULUS);
    BIG_256_56_modadd(s1, tmp, t1, MODULUS);

    BIG_256_56_modmul(tmp, message[0], c, MODULUS);
    BIG_256_56_modadd(s2[0], tmp, t2[0], MODULUS);
    
    for(int i = 1; i < sig->l; i++) {
        BIG_256_56_modmul(tmp, message[i], c, MODULUS);
        BIG_256_56_modadd(s2[i], tmp, t2[i], MODULUS);
    }
}


int PoK_verifier(BIG_256_56 s1, BIG_256_56 *s2, BIG_256_56 c, FP12_BN254 *T, FP12_BN254 *commitment,
                 schemeD_public_key *public_key, schemeD_signature *blind_sig) {

    int res = 0;

    FP12_BN254 Vx, Vxy, Vxy_i, prod, lhs, rhs;
    ECP_BN254 B_times_s_i, b_blind, a_blind;

    FP12_BN254_one(&prod);
    FP12_BN254_one(&lhs);
    FP12_BN254_one(&rhs);

    ECP_BN254_copy(&a_blind, &blind_sig->a);
    PAIR_BN254_G1mul(&a_blind, s1);
    PAIR_BN254_ate(&Vx, &public_key->X, &a_blind);
    PAIR_BN254_fexp(&Vx);

    ECP_BN254_copy(&b_blind, &blind_sig->b);
    PAIR_BN254_G1mul(&b_blind, s2[0]);
    PAIR_BN254_ate(&Vxy, &public_key->X, &b_blind);
    PAIR_BN254_fexp(&Vxy);

    for(int i = 1; i < public_key->l; i++) {
        ECP_BN254_copy(&B_times_s_i, &blind_sig->B[i]);
        PAIR_BN254_G1mul(&B_times_s_i, s2[i]);

        PAIR_BN254_ate(&Vxy_i, &public_key->X, &B_times_s_i);
        PAIR_BN254_fexp(&Vxy_i);

        FP12_BN254_mul(&prod, &Vxy_i);
    }

    FP12_BN254_mul(&lhs, &Vx);
    FP12_BN254_mul(&lhs, &Vxy);
    FP12_BN254_mul(&lhs, &prod);

    FP12_BN254_pow(&rhs, commitment, c);
    FP12_BN254_mul(&rhs, T);

    FP12_BN254_equals(&lhs, &rhs) ? res++ : (res = 0);

    int v = 0;

    for(int i = 0; i < public_key->l; i++) {
        v += pairing_and_equality_check(&public_key->Z[i], &blind_sig->a, &public_key->g_2, &blind_sig->A[i]);
        v += pairing_and_equality_check(&public_key->Y, &blind_sig->A[i], &public_key->g_2, &blind_sig->B[i]);
    }

    if(v == public_key->l * 2) res++;

    pairing_and_equality_check(&public_key->Y, &blind_sig->a, &public_key->g_2, &blind_sig->b) ? res++ : (res = 0);

    return res;
}