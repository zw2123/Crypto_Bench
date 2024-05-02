#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/resource.h>

#define DATA_SIZE (1024 * 1024 * 50)  // 50 MB for throughput calculation
#define ITERATIONS 10

struct benchmark_stats {
    double keygen_time;    // milliseconds
    double encaps_time;    // milliseconds
    double decaps_time;    // milliseconds
    double total_time;     // milliseconds
    double cpu_user_time;  // milliseconds
    double cpu_system_time;// milliseconds
    double throughput;     // MB/s
    int thread_id;
};

void handleErrors(void) {
    fprintf(stderr, "An error occurred\n");
    abort();
}

void get_cpu_times(double *user_time, double *system_time) {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);  // Changed from RUSAGE_THREAD to RUSAGE_SELF
    *user_time = usage.ru_utime.tv_sec * 1000.0 + usage.ru_utime.tv_usec / 1000.0;
    *system_time = usage.ru_stime.tv_sec * 1000.0 + usage.ru_stime.tv_usec / 1000.0;
}

void *perform_kyber_operations(void *args) {
    struct benchmark_stats *stats = (struct benchmark_stats *)args;
    const char *alg_name = (stats->thread_id % 2 == 0) ? OQS_KEM_alg_kyber_512 : OQS_KEM_alg_kyber_1024;
    OQS_KEM *kem = OQS_KEM_new(alg_name);

    uint8_t public_key[kem->length_public_key];
    uint8_t secret_key[kem->length_secret_key];
    uint8_t ciphertext[kem->length_ciphertext];
    uint8_t shared_secret_e[kem->length_shared_secret];
    uint8_t shared_secret_d[kem->length_shared_secret];

    struct timeval start, end;
    double start_user, start_system, end_user, end_system;
    double keygen_time = 0, encaps_time = 0, decaps_time = 0;

    get_cpu_times(&start_user, &start_system);

    for (int i = 0; i < ITERATIONS; i++) {
        // Key Generation
        gettimeofday(&start, NULL);
        OQS_KEM_keypair(kem, public_key, secret_key);
        gettimeofday(&end, NULL);
        keygen_time += (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;

        // Encapsulation
        gettimeofday(&start, NULL);
        OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
        gettimeofday(&end, NULL);
        encaps_time += (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;

        // Decapsulation
        gettimeofday(&start, NULL);
        OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
        gettimeofday(&end, NULL);
        decaps_time += (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
    }

    get_cpu_times(&end_user, &end_system);

    stats->keygen_time = keygen_time / ITERATIONS;
    stats->encaps_time = encaps_time / ITERATIONS;
    stats->decaps_time = decaps_time / ITERATIONS;
    stats->total_time = stats->keygen_time + stats->encaps_time + stats->decaps_time;
    stats->cpu_user_time = end_user - start_user;
    stats->cpu_system_time = end_system - start_system;
    double data_processed_per_iter = kem->length_public_key + kem->length_secret_key + kem->length_ciphertext + kem->length_shared_secret;
    stats->throughput = (data_processed_per_iter * ITERATIONS / 1024.0 / 1024.0) / (stats->total_time / 1000.0);  // MB per second

    OQS_KEM_free(kem);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2 || (strcmp(argv[1], "128") != 0 && strcmp(argv[1], "256") != 0)) {
        fprintf(stderr, "Usage: %s <128|256>\n", argv[0]);
        return 1;
    }
    int key_size = (strcmp(argv[1], "128") == 0) ? 128 : 256;

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

    for (int i = 0; i < num_threads; i++) {
        printf("Thread %d: Key Generation Time: %.2f ms, Encapsulation Time: %.2f ms, Decapsulation Time: %.2f ms, Total Time: %.2f ms, CPU User Time: %.2f ms, CPU System Time: %.2f ms, Throughput: %.2f MB/s\n",
               stats[i].thread_id, stats[i].keygen_time, stats[i].encaps_time, stats[i].decaps_time, stats[i].total_time, stats[i].cpu_user_time, stats[i].cpu_system_time, stats[i].throughput);
    }

    return 0;
}
