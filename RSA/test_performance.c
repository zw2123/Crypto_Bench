/*The code is designed to perform RSA encryption and decryption operations across multiple threads, benchmarking their 
performance in terms of time and throughput.

1. perform_rsa_encryption_decryption(void *args) is the function that each thread executes. It handles the process of setting 
   up RSA keys, performing encryption and decryption, and calculating the time taken for these operations.

2. Memory for plaintext, ciphertext, and decrypted text is dynamically allocated.

3. An RSA key is generated using OpenSSL's EVP functions. The size of the RSA key (in bits) is controlled by the thread_id parameter, 
   which should actually represent key_size.

4. The function measures the time taken for encryption and decryption using clock_gettime(), specifically measuring both real 
   time (wall-clock time) and CPU time to assess performance and efficiency.*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <float.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#define DATA_SIZE 200  // Max data size for RSA encryption with OAEP padding
#define ITERATIONS 10

struct benchmark_stats {
    double enc_time; // milliseconds
    double dec_time; // milliseconds
    double total_time; // milliseconds
    double throughput; // MB/s
    double thread_cpu_time;  // milliseconds
    int thread_id;
};

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void *perform_rsa_encryption_decryption(void *args) {
    struct benchmark_stats *stats = (struct benchmark_stats *)args;
    unsigned char *plaintext = malloc(DATA_SIZE);
    unsigned char *ciphertext, *decryptedtext;
    size_t outlen, decryptedlen;

    if (!plaintext) {
        fprintf(stderr, "Memory allocation failed\n");
        handleErrors();
    }

    RAND_bytes(plaintext, DATA_SIZE);

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, stats->thread_id) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0)
        handleErrors();

    // Allocate memory for ciphertext based on the size of the RSA key
    ciphertext = malloc(EVP_PKEY_get_size(pkey));
    decryptedtext = malloc(DATA_SIZE);

    if (!ciphertext || !decryptedtext) {
        fprintf(stderr, "Memory allocation failed\n");
        handleErrors();
    }

    EVP_PKEY_CTX_free(ctx); // Free the keygen context

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) handleErrors();

    struct timespec start, end, cpu_start, cpu_end;
    double enc_time = 0, dec_time = 0;

    // Start CPU time measurement
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_start);

    for (int i = 0; i < ITERATIONS; i++) {
        // Encryption
        EVP_PKEY_encrypt_init(ctx);
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
        if (EVP_PKEY_encrypt(ctx, NULL, &outlen, plaintext, DATA_SIZE) <= 0)
            handleErrors();

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (EVP_PKEY_encrypt(ctx, ciphertext, &outlen, plaintext, DATA_SIZE) <= 0)
            handleErrors();
        clock_gettime(CLOCK_MONOTONIC, &end);
        enc_time += (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;

        // Decryption
        EVP_PKEY_decrypt_init(ctx);
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
        if (EVP_PKEY_decrypt(ctx, NULL, &decryptedlen, ciphertext, outlen) <= 0)
            handleErrors();

        if (EVP_PKEY_decrypt(ctx, decryptedtext, &decryptedlen, ciphertext, outlen) <= 0)
            handleErrors();
    }

    // End CPU time measurement
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_end);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    free(plaintext);
    free(ciphertext);
    free(decryptedtext);

    stats->enc_time = enc_time / ITERATIONS;
    stats->dec_time = dec_time / ITERATIONS;
    stats->total_time = stats->enc_time + stats->dec_time;
    stats->throughput = (double)DATA_SIZE * ITERATIONS / (1024.0 * 1024.0 * (stats->total_time / 1000.0));
    stats->thread_cpu_time = (cpu_end.tv_sec - cpu_start.tv_sec) * 1000.0 + (cpu_end.tv_nsec - cpu_start.tv_nsec) / 1e6;

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <2048|4096>\n", argv[0]);
        return 1;
    }

    int key_size = atoi(argv[1]);
    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    pthread_t threads[num_threads];
    struct benchmark_stats stats[num_threads];

    for (int i = 0; i < num_threads; i++) {
        stats[i].thread_id = key_size;
        pthread_create(&threads[i], NULL, perform_rsa_encryption_decryption, &stats[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
        printf("Thread %d: Average Encryption/Decryption Time: %.2f ms, Throughput: %.2f MB/s, Thread CPU Time: %.2f ms\n",
               stats[i].thread_id, stats[i].total_time, stats[i].throughput, stats[i].thread_cpu_time);
    }

    return 0;
}