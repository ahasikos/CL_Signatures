//
// Created by Alexandros Hasikos on 08/07/2021.
//

#include "pairings_test.h"
#include <bls_BN254.h>
#include <ecp_BN254.h>

int pairings_test() {
    //---------------------------------------------------
    // Init
    //---------------------------------------------------
    if(BLS_BN254_INIT() != BLS_OK) {
        printf("Error\n");
        exit(1);
    }
    //---------------------------------------------------



    //---------------------------------------------------
    // Declare and seed prng
    //---------------------------------------------------
    char seed[20] = {0};
    csprng prng;

    RAND_seed(&prng, sizeof(seed), seed);
    //---------------------------------------------------


    //---------------------------------------------------
    // Test pairings
    //---------------------------------------------------
    char rand_oct_mem[128] = {0};
    octet rand_oct = {0, sizeof(rand_oct_mem), rand_oct_mem};

    OCT_rand(&rand_oct, &prng, sizeof(rand_oct_mem));

    //Create G1
    ECP_BN254 G1;
    ECP_BN254_generator(&G1);

    //Mul x * G1
    ECP_BN254 x_times_G1;
    BIG_256_56 x;
    BIG_256_56_random(x, &prng);
    ECP_BN254_copy(&x_times_G1, &G1);
    PAIR_BN254_G1mul(&x_times_G1, x);


    //Create G2
    ECP2_BN254 G2;
    ECP2_BN254_generator(&G2);

    //Mul y * G2
    ECP2_BN254 y_times_G2;
    BIG_256_56 y;
    BIG_256_56_random(y, &prng);
    ECP2_BN254_copy(&y_times_G2, &G2);
    PAIR_BN254_G2mul(&y_times_G2, y);


    //Pairing
    FP12_BN254 p;
    PAIR_BN254_ate(&p, &y_times_G2, &x_times_G1);
    PAIR_BN254_fexp(&p);
    FP12_BN254_output(&p);
    putchar(10);


    //Verification that it works
    BIG_256_56 x_times_y, one;
    BIG_256_56_one(one);
    BIG_256_56_modmul(x_times_y, x, y, (int64_t *)CURVE_Order_BN254);

    ECP_BN254 G1_times_xy;
    ECP_BN254_copy(&G1_times_xy, &G1);
    PAIR_BN254_G1mul(&G1_times_xy, x_times_y);

    ECP2_BN254 G2_times_1;
    ECP2_BN254_copy(&G2_times_1, &G2);
    PAIR_BN254_G2mul(&G2_times_1, one);

    FP12_BN254 p2;
    PAIR_BN254_ate(&p2, &G2_times_1, &G1_times_xy);
    PAIR_BN254_fexp(&p2);
    FP12_BN254_output(&p2);
    putchar(10);


    if(FP12_BN254_equals(&p, &p2) == 1) {
        printf("Equal\n");
    } else {
        printf("NOT Equal\n");
    }

    //---------------------------------------------------


    return 0;
}
