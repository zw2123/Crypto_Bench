/*How does this work:
1.Environment Setup: Initializes multi-threading to utilize all available CPU cores, setting up a separate thread for each core to 
  parallelize the hashing process.

2.Data Preparation:Each thread allocates a 50 MB buffer and fills it with random bytes using RAND_bytes. This simulates a realistic 
  scenario where large data chunks are processed.

3.Each thread creates a hash context with EVP_MD_CTX_new.The hashing algorithm (SHA-1 or SHA-256) is set based on user input.

4.The data is hashed in a loop over ten iterations to ensure statistical significance. Time measurement for each hashing operation 
  is captured using clock_gettime with CLOCK_MONOTONIC, marking the start and end of each hash computation.

5.The total time taken for all iterations is calculated and averaged to determine the mean hash time per iteration. Throughput is 
  computed as the total amount of data processed divided by the total time, providing a measure of MB/s.

6.CPU time used by the thread is measured using clock_gettime with CLOCK_THREAD_CPUTIME_ID, capturing the CPU time dedicated to the 
  thread's process.*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <time.h>
#include <sys/resource.h>
#include <pthread.h>
#include <unistd.h>

#define DATA_SIZE (1024 * 1024 * 50)  // 50 MB
#define ITERATIONS 10

struct benchmark_stats {
    double hash_time; // milliseconds
    double total_time; // milliseconds
    double throughput; // MB/s
    double cpu_user_time; // milliseconds
    double cpu_system_time;
    double thread_cpu_time;  // milliseconds
    int thread_id;
};

const EVP_MD *digest = NULL;

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void get_cpu_times(double *user_time, double *system_time) {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    *user_time = usage.ru_utime.tv_sec * 1000.0 + usage.ru_utime.tv_usec / 1000.0;
    *system_time = usage.ru_stime.tv_sec * 1000.0 + usage.ru_stime.tv_usec / 1000.0;
}

void *perform_hashing(void *args) {
    struct benchmark_stats *stats = (struct benchmark_stats *)args;
    unsigned char *data = malloc(DATA_SIZE);
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    if (!data) {
        fprintf(stderr, "Memory allocation failed\n");
        handleErrors();
    }

    RAND_bytes(data, DATA_SIZE);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) handleErrors();

    struct timespec start, end, cpu_start, cpu_end;
    double hash_time = 0;

    // Get initial CPU time for this thread
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_start) != 0) {
        handleErrors();
    }

    for (int i = 0; i < ITERATIONS; i++) {
        EVP_MD_CTX_reset(mdctx);
        if (1 != EVP_DigestInit_ex(mdctx, digest, NULL)) handleErrors();

        clock_gettime(CLOCK_MONOTONIC, &start);
        if (1 != EVP_DigestUpdate(mdctx, data, DATA_SIZE)) handleErrors();
        if (1 != EVP_DigestFinal_ex(mdctx, md_value, &md_len)) handleErrors();
        clock_gettime(CLOCK_MONOTONIC, &end);

        hash_time += (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;
    }

    // Get final CPU time for this thread
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &cpu_end) != 0) {
        handleErrors();
    }

    double cpu_time_used = (cpu_end.tv_sec - cpu_start.tv_sec) * 1000.0 + (cpu_end.tv_nsec - cpu_start.tv_nsec) / 1e6;

    EVP_MD_CTX_free(mdctx);
    free(data);

    stats->hash_time = hash_time / ITERATIONS;
    stats->total_time = stats->hash_time;
    stats->throughput = (double)DATA_SIZE * ITERATIONS / (1024.0 * 1024.0 * (stats->total_time / 1000.0));
    stats->thread_cpu_time = cpu_time_used;

    return NULL;
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <1|256>\n", argv[0]);
        return 1;
    }

    int digest_type = atoi(argv[1]);
    switch (digest_type) {
        case 1:
            digest = EVP_sha1();
            break;
        case 256:
            digest = EVP_sha256();
            break;
        default:
            fprintf(stderr, "Invalid digest type: %s. Use 1 for SHA-1, 256 for SHA-256.\n", argv[1]);
            return 1;
    }

    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    pthread_t threads[num_threads];
    struct benchmark_stats stats[num_threads];

    for (int i = 0; i < num_threads; i++) {
        stats[i].thread_id = i;
        pthread_create(&threads[i], NULL, perform_hashing, &stats[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    for (int i = 0; i < num_threads; i++) {
    pthread_join(threads[i], NULL);
    printf("Thread %d: Hash Time: %.2f ms, Total Time: %.2f ms, Throughput: %.2f MB/s, Thread CPU Time: %.2f ms\n",
           stats[i].thread_id, stats[i].hash_time, stats[i].total_time, stats[i].throughput, stats[i].thread_cpu_time);
    }

    return 0;
}
