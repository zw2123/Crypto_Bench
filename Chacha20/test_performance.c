/*How does this work:
  
The program leverages multi-threading to parallelize encryption and decryption tasks, allowing performance testing under a simulated 
load.It provides detailed timing for encryption and decryption separately and together, as well as the throughput in MB/s and the CPU 
time used for cryptographic operations.
*/

/*How does this work:
  
The program leverages multi-threading to parallelize encryption and decryption tasks, allowing performance testing under a simulated 
load.It provides detailed timing for encryption and decryption separately and together, as well as the throughput in MB/s and the CPU 
time used for cryptographic operations.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

#define DATA_SIZE (1024 * 1024 * 50)  // 50 MB
#define ITERATIONS 10
#define NUM_THREADS 4  

struct benchmark_stats {
    double enc_time; // milliseconds
    double dec_time; // milliseconds
    double total_time; // milliseconds
    double throughput; // MB/s
    double cpu_time;   // CPU time in milliseconds
    int thread_id; // Identifier for the thread
};

const EVP_CIPHER *cipher = NULL;

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void *perform_encryption_decryption(void *args) {
    struct benchmark_stats *stats = (struct benchmark_stats *)args;
    unsigned char key[32], iv[12]; // ChaCha20 uses 256-bit key and 96-bit IV
    unsigned char *plaintext = malloc(DATA_SIZE);
    unsigned char *ciphertext = malloc(DATA_SIZE);
    unsigned char *decryptedtext = malloc(DATA_SIZE);

    if (!ciphertext || !decryptedtext || !plaintext) {
        fprintf(stderr, "Memory allocation failed\n");
        handleErrors();
    }

    RAND_bytes(plaintext, DATA_SIZE);
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    struct timespec start, end, cpu_start, cpu_end;
    double enc_time = 0, dec_time = 0, cpu_time = 0;

    // Start CPU time measurement
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_start);

    for (int i = 0; i < ITERATIONS; i++) {
        int len;

        // Encryption
        EVP_CIPHER_CTX_reset(ctx);
        if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) handleErrors();
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, DATA_SIZE)) handleErrors();
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
        clock_gettime(CLOCK_MONOTONIC, &end);
        enc_time += (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;

        // Decryption
        EVP_CIPHER_CTX_reset(ctx);
        if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) handleErrors();
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (1 != EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, DATA_SIZE)) handleErrors();
        if (1 != EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len)) handleErrors();
        clock_gettime(CLOCK_MONOTONIC, &end);
        dec_time += (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;
    }

    // End CPU time measurement
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_end);
    cpu_time = (cpu_end.tv_sec - cpu_start.tv_sec) * 1000.0 + (cpu_end.tv_nsec - cpu_start.tv_nsec) / 1e6;

    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    free(decryptedtext);
    free(plaintext);

    stats->enc_time = enc_time / ITERATIONS;
    stats->dec_time = dec_time / ITERATIONS;
    stats->total_time = stats->enc_time + stats->dec_time;
    stats->throughput = (double)DATA_SIZE * ITERATIONS / (1024.0 * 1024.0 * (stats->total_time / 1000.0));
    stats->cpu_time = cpu_time; // Store the total CPU time used by this thread

    return NULL;
}

int main() {
    cipher = EVP_chacha20();
    if (!cipher) {
        fprintf(stderr, "Failed to initialize cipher.\n");
        return 1;
    }

    pthread_t threads[NUM_THREADS];
    struct benchmark_stats stats[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        stats[i].thread_id = i + 1; // Starting thread ID from 1 for output
        pthread_create(&threads[i], NULL, perform_encryption_decryption, &stats[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        printf("Thread %d: Encryption Time: %.2f ms, Decryption Time: %.2f ms, Total Time: %.2f ms, Throughput: %.2f MB/s, CPU Time: %.2f ms\n",
               stats[i].thread_id, stats[i].enc_time, stats[i].dec_time, stats[i].total_time, stats[i].throughput, stats[i].cpu_time);
    }

    return 0;
}
