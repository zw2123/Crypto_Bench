/*How does this work:

The code is a multi-threaded benchmarking program designed to measure the performance of the RIPEMD-160 hash function from the OpenSSL 
library.After all threads complete their execution, the program prints detailed statistics for each thread, including:

1. Hash time per iteration (average).
2. Total elapsed time for all iterations.
3. Data throughput in megabytes per second.
4. CPU time used.*/

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
    double hash_time;  // milliseconds
    double total_time; // milliseconds
    double throughput; // MB/s
    double cpu_time;   // CPU time in milliseconds
    int thread_id;     // Identifier for the thread
};

const EVP_MD *hash_function = NULL;

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void *perform_hashing(void *args) {
    struct benchmark_stats *stats = (struct benchmark_stats *)args;
    unsigned char *data = malloc(DATA_SIZE);
    unsigned char md[EVP_MAX_MD_SIZE]; // Enough space for the largest possible hash
    unsigned int md_len;

    if (!data) {
        fprintf(stderr, "Memory allocation failed\n");
        handleErrors();
    }

    RAND_bytes(data, DATA_SIZE);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) handleErrors();

    struct timespec start, end, cpu_start, cpu_end;
    double hash_time = 0, cpu_time = 0;

    // Start CPU time measurement
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_start);

    for (int i = 0; i < ITERATIONS; i++) {
        EVP_MD_CTX_reset(mdctx);
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (1 != EVP_DigestInit_ex(mdctx, EVP_ripemd160(), NULL)) handleErrors();
        if (1 != EVP_DigestUpdate(mdctx, data, DATA_SIZE)) handleErrors();
        if (1 != EVP_DigestFinal_ex(mdctx, md, &md_len)) handleErrors();
        clock_gettime(CLOCK_MONOTONIC, &end);
        hash_time += (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;
    }

    // End CPU time measurement
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_end);
    cpu_time = (cpu_end.tv_sec - cpu_start.tv_sec) * 1000.0 + (cpu_end.tv_nsec - cpu_start.tv_nsec) / 1e6;

    EVP_MD_CTX_free(mdctx);
    free(data);

    stats->hash_time = hash_time / ITERATIONS;
    stats->total_time = stats->hash_time;
    stats->throughput = (double)DATA_SIZE * ITERATIONS / (1024.0 * 1024.0 * (stats->total_time / 1000.0));
    stats->cpu_time = cpu_time; 

    return NULL;
}

int main() {
    hash_function = EVP_ripemd160();
    if (!hash_function) {
        fprintf(stderr, "Failed to initialize RIPEMD-160 hash function.\n");
        return 1;
    }

    pthread_t threads[NUM_THREADS];
    struct benchmark_stats stats[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; i++) {
        stats[i].thread_id = i + 1; 
        pthread_create(&threads[i], NULL, perform_hashing, &stats[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        printf("Thread %d: Hash Time: %.2f ms, Total Time: %.2f ms, Throughput: %.2f MB/s, CPU Time: %.2f ms\n",
               stats[i].thread_id, stats[i].hash_time, stats[i].total_time, stats[i].throughput, stats[i].cpu_time);
    }

    return 0;
}
