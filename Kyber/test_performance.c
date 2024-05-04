/*How does this work:
The code performs a performance test for the Kyber key encapsulation mechanism (KEM) using the Open Quantum Safe library. 

1. Setup: It initializes the Kyber KEM instance and allocates memory for public keys, secret keys, ciphertext, and shared secrets.

2. Key Generation: Measures the time taken to generate a key pair (public and secret keys).

3. Encapsulation: Measures the time taken to encapsulate a secret (generating ciphertext and a shared secret for encryption).

4. Decapsulation: Measures the time taken to decapsulate (recovering the shared secret from the ciphertext using the secret key).

5. Performance Measurement: It records the time taken for each operation (key generation, encapsulation, decapsulation) over multiple 
   iterations to calculate average times.

6. Multi-threading: The test is run on multiple threads simultaneously, with each thread performing the complete set of operations 
   repeatedly, allowing the measurement of performance under concurrent operations.

6. Reporting: At the end of the testing, it reports the average times for each operation and the total processing time per thread, 
   along with the thread's CPU time.*/
   
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

#define ITERATIONS 1000  // Increased to provide more stable measurement

struct benchmark_stats {
    double keygen_time;    // milliseconds
    double encaps_time;    // milliseconds
    double decaps_time;    // milliseconds
    double total_time;     // milliseconds
    double thread_cpu_time;  // milliseconds
    int thread_id;
};

void handleErrors(const char* message) {
    fprintf(stderr, "Error: %s\n", message);
    abort();
}

void *perform_kyber_operations(void *args) {
    struct benchmark_stats *stats = (struct benchmark_stats *)args;
    const char *alg_name = (stats->thread_id % 2 == 0) ? OQS_KEM_alg_kyber_512 : OQS_KEM_alg_kyber_1024;
    OQS_KEM *kem = OQS_KEM_new(alg_name);
    if (!kem) {
        handleErrors("OQS_KEM_new failed");
    }

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_e = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_d = malloc(kem->length_shared_secret);

    struct timespec start, end, cpu_start, cpu_end;
    double keygen_time = 0, encaps_time = 0, decaps_time = 0;

    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_start) != 0) {
        handleErrors("Failed to get CPU start time");
    }

    for (int i = 0; i < ITERATIONS; i++) {
        // Key Generation
        clock_gettime(CLOCK_MONOTONIC, &start);
        OQS_KEM_keypair(kem, public_key, secret_key);
        clock_gettime(CLOCK_MONOTONIC, &end);
        keygen_time += (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;

        // Encapsulation
        clock_gettime(CLOCK_MONOTONIC, &start);
        OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
        clock_gettime(CLOCK_MONOTONIC, &end);
        encaps_time += (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;

        // Decapsulation
        clock_gettime(CLOCK_MONOTONIC, &start);
        OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
        clock_gettime(CLOCK_MONOTONIC, &end);
        decaps_time += (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;
    }

    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_end) != 0) {
        handleErrors("Failed to get CPU end time");
    }

    OQS_KEM_free(kem);
    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret_e);
    free(shared_secret_d);

    stats->keygen_time = keygen_time / ITERATIONS;
    stats->encaps_time = encaps_time / ITERATIONS;
    stats->decaps_time = decaps_time / ITERATIONS;
    stats->total_time = stats->keygen_time + stats->encaps_time + stats->decaps_time;
    stats->thread_cpu_time = (cpu_end.tv_sec - cpu_start.tv_sec) * 1000.0 + (cpu_end.tv_nsec - cpu_start.tv_nsec) / 1e6;

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2 || (strcmp(argv[1], "128") != 0 && strcmp(argv[1], "256") != 0)) {
        fprintf(stderr, "Usage: %s <128|256>\n", argv[0]);
        return 1;
    }

    struct timespec total_start, total_end;
    clock_gettime(CLOCK_MONOTONIC, &total_start);  // Start profiling

    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    pthread_t threads[num_threads];
    struct benchmark_stats stats[num_threads];

    for (int i = 0; i < num_threads; i++) {
        stats[i].thread_id = i;
        pthread_create(&threads[i], NULL, perform_kyber_operations, &stats[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    clock_gettime(CLOCK_MONOTONIC, &total_end);  // End profiling
    double total_time = (total_end.tv_sec - total_start.tv_sec) * 1000.0 + (total_end.tv_nsec - total_start.tv_nsec) / 1e6;
    printf("Total elapsed time for all threads: %.2f ms\n", total_time);

    for (int i = 0; i < num_threads; i++) {
        printf("Thread %d: Key Generation Time: %.2f ms, Encryption Time: %.2f ms, Decryption Time: %.2f ms, Total Time: %.2f ms, Thread CPU Time: %.2f ms\n",
               stats[i].thread_id, stats[i].keygen_time, stats[i].encaps_time, stats[i].decaps_time, stats[i].total_time, stats[i].thread_cpu_time);
    }

    return 0;
}
