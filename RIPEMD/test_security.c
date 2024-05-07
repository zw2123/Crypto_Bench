#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <time.h>
#include <math.h>

#define DATA_SIZE (1024 * 1024 * 50) // 50 MB

typedef struct {
    int thread_id;
    unsigned char *data;
    int data_len;
    int success;
    char hash_output[41]; // RIPEMD-160 outputs a 40-character hexadecimal hash
} ThreadData;

void handleErrors(const char* error) {
    fprintf(stderr, "Error: %s\n", error);
    abort();
}

EVP_MD_CTX* initialize_ripemd160_context() {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create EVP_MD_CTX\n");
        return NULL;
    }
    if (1 != EVP_DigestInit_ex(ctx, EVP_ripemd160(), NULL)) {
        EVP_MD_CTX_free(ctx);
        fprintf(stderr, "Failed to initialize RIPEMD-160 context\n");
        return NULL;
    }
    return ctx;
}

void ripemd160_hash(EVP_MD_CTX *ctx, unsigned char *input, unsigned char *output, int length) {
    unsigned int output_length;
    EVP_DigestUpdate(ctx, input, length);
    EVP_DigestFinal_ex(ctx, output, &output_length);
}

void initialize_thread_data(ThreadData *data, int thread_id) {
    data->thread_id = thread_id;
    data->data = malloc(DATA_SIZE);
    if (!data->data) {
        handleErrors("Memory allocation failed for data buffer");
    }
    memset(data->data, 0, DATA_SIZE); // Initialize with zeroes or any pattern
    data->data_len = DATA_SIZE;
    data->success = 0; // Initialize with failed status, will be set to 1 if successful
}


void *hash_replicated_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char *output1 = malloc(EVP_MD_size(EVP_ripemd160()));
    unsigned char *output2 = malloc(EVP_MD_size(EVP_ripemd160()));

    if (!output1 || !output2) {
        fprintf(stderr, "Memory allocation error in hash_replicated_test\n");
        data->success = 0; // Indicate failure
        free(output1);
        free(output2);
        return NULL;
    }

    EVP_MD_CTX *ctx1 = initialize_ripemd160_context();
    ripemd160_hash(ctx1, data->data, output1, data->data_len);
    EVP_MD_CTX_free(ctx1);

    EVP_MD_CTX *ctx2 = initialize_ripemd160_context();
    ripemd160_hash(ctx2, data->data, output2, data->data_len);
    EVP_MD_CTX_free(ctx2);

    // Compare the results of the two hashing operations
    if (memcmp(output1, output2, EVP_MD_size(EVP_ripemd160())) != 0) {
        fprintf(stderr, "Discrepancy detected in outputs!\n");
        data->success = 0;
    } else {
        printf("Test successful: No discrepancy detected in outputs for Thread %d.\n", data->thread_id);
        data->success = 1; // Indicate success
    }

    free(output1);
    free(output2);
    return NULL;
}

void *hash_timing_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;

    int num_trials = 20;
    double *times = malloc(num_trials * sizeof(double));
    if (!times) {
        fprintf(stderr, "Failed to allocate memory for timing data\n");
        data->success = 0;
        return NULL;
    }

    double sum = 0.0, mean, standard_deviation = 0.0;
    EVP_MD_CTX *ctx = NULL;
    unsigned char *output = NULL;

    for (int i = 0; i < num_trials; i++) {
        output = malloc(EVP_MD_size(EVP_ripemd160()));
        ctx = initialize_ripemd160_context();

        if (!output || !ctx) {
            fprintf(stderr, "Allocation failed for output buffer or context on trial %d\n", i);
            if (output) {
                free(output);
            }
            if (ctx) {
                EVP_MD_CTX_free(ctx);
            }
            free(times); // Free times array as we are exiting due to a failure
            data->success = 0;
            return NULL;
        }

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        unsigned int len;
        EVP_DigestUpdate(ctx, data->data, data->data_len);
        EVP_DigestFinal_ex(ctx, output, &len);
        clock_gettime(CLOCK_MONOTONIC, &end);

        times[i] = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        sum += times[i];

        free(output);
        EVP_MD_CTX_free(ctx);
    }

    mean = sum / num_trials;
    for (int i = 0; i < num_trials; i++) {
        standard_deviation += pow(times[i] - mean, 2);
    }
    standard_deviation = sqrt(standard_deviation / num_trials);
    double cv = (standard_deviation / mean) * 100;

    printf("Timing Analysis Results for Thread %d:\n", data->thread_id);
    printf("Mean Time: %.9f seconds, Standard Deviation: %.9f seconds, CV: %.2f%%\n", mean, standard_deviation, cv);

    if (cv < 1.0) {
        printf("Low risk of timing side-channel leakage.\n");
    } else if (cv < 5.0) {
        printf("Moderate risk of timing side-channel leakage. Consider further investigation.\n");
    } else {
        printf("High risk of timing side-channel leakage. Immediate action recommended.\n");
    }

    free(times);
    data->success = 1;
    return NULL;
}

void *hash_row_hammer_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char *output1 = malloc(EVP_MD_size(EVP_ripemd160()));
    unsigned char *output2 = malloc(EVP_MD_size(EVP_ripemd160()));
    int flip_position;

    if (!output1 || !output2) {
        fprintf(stderr, "Memory allocation error in hash_row_hammer_test\n");
        return NULL;
    }

    EVP_MD_CTX *ctx = initialize_ripemd160_context();
    ripemd160_hash(ctx, data->data, output1, data->data_len);

    srand(time(NULL)); // Seed random number generator
    for (int i = 0; i < 100; i++) {  // Simulate multiple hits to potentially flip bits
        flip_position = rand() % (data->data_len * 8);  
        data->data[flip_position / 8] ^= (1 << (flip_position % 8));  // Flip the bit
    }

    ripemd160_hash(ctx, data->data, output2, data->data_len);

    // Compare the hash outputs
    if (memcmp(output1, output2, EVP_MD_size(EVP_ripemd160())) == 0) {
        printf("No change in output despite fault injection for Thread %d.\n", data->thread_id);
    } else {
        printf("Fault injection altered the output for Thread %d.\n", data->thread_id);
    }

    EVP_MD_CTX_free(ctx);
    free(output1);
    free(output2);
    data->success = 1;
    return NULL;
}

void *hash_brute_force_speed_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    printf("Starting brute force speed test for Thread %d\n", data->thread_id);

    unsigned char *computed_hash = malloc(EVP_MD_size(EVP_ripemd160()));
    if (!computed_hash) {
        fprintf(stderr, "Memory allocation error in hash_brute_force_speed_test\n");
        return NULL;
    }

    unsigned char *test_input = malloc(DATA_SIZE);
    if (!test_input) {
        fprintf(stderr, "Memory allocation error for test input buffer\n");
        free(computed_hash);
        return NULL;
    }

    int warmup_duration_seconds = 15;
    int test_duration_seconds = 15;
    unsigned long long num_hashes_computed = 0;
    time_t end_time, start_time, warmup_end_time;

    // Warm-up phase
    start_time = time(NULL);
    do {
        for (int i = 0; i < 256; i++) { // Very simple brute force: test 256 different inputs
            memset(test_input, i, DATA_SIZE);
            EVP_MD_CTX *ctx = initialize_ripemd160_context();
            if (!ctx) {
                fprintf(stderr, "RIPEMD-160 context initialization failed in brute force test\n");
                free(test_input);
                free(computed_hash);
                return NULL;
            }
            ripemd160_hash(ctx, test_input, computed_hash, DATA_SIZE);
            EVP_MD_CTX_free(ctx);
            num_hashes_computed++;
        }
        warmup_end_time = time(NULL);
    } while (difftime(warmup_end_time, start_time) < warmup_duration_seconds);

    printf("Warm-up phase completed for Thread %d\n", data->thread_id);

    start_time = time(NULL); // Start timing

    do {
        for (int i = 0; i < 256; i++) { // Very simple brute force: test 256 different inputs
            memset(test_input, i, DATA_SIZE);
            EVP_MD_CTX *ctx = initialize_ripemd160_context();
            if (!ctx) {
                fprintf(stderr, "RIPEMD-160 context initialization failed in brute force test\n");
                free(test_input);
                free(computed_hash);
                return NULL;
            }
            ripemd160_hash(ctx, test_input, computed_hash, DATA_SIZE);
            EVP_MD_CTX_free(ctx);

            num_hashes_computed++;

            // Assuming we know the hash we're looking for, compare here
            if (memcmp(computed_hash, data->data, EVP_MD_size(EVP_ripemd160())) == 0) {
                double hashes_per_second = num_hashes_computed / difftime(time(NULL), start_time);
                double estimated_time_seconds = (pow(2, 160) / hashes_per_second);
                printf("Estimated time to break RIPEMD-160: %.2e years\n", estimated_time_seconds / (60 * 60 * 24 * 365));
                free(test_input);
                free(computed_hash);
                data->success = 1;
                return NULL;
            }
        }

        end_time = time(NULL);
    } while (difftime(end_time, start_time) < test_duration_seconds);

    double hashes_per_second = num_hashes_computed / difftime(end_time, start_time);
    double estimated_time_seconds = (pow(2, 160) / hashes_per_second);
    printf("Estimated time to break RIPEMD-160: %.2e years\n", estimated_time_seconds / (60 * 60 * 24 * 365));

    free(test_input);
    free(computed_hash);
    data->success = 0;
    return NULL;
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <timing|replicated|rowhammer|bruteforce>\n", argv[0]);
        return 1;
    }

    char *mode = argv[1];
    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    ThreadData *thread_data = calloc(num_threads, sizeof(ThreadData));

    if (!threads || !thread_data) {
        fprintf(stderr, "Failed to allocate memory for threads or thread data\n");
        return 1;
    }

    void *(*function_pointer)(void *) = NULL;

    if (strcmp(mode, "replicated") == 0) {
        function_pointer = hash_replicated_test;
    } else if (strcmp(mode, "timing") == 0) {
        function_pointer = hash_timing_test;
    } else if (strcmp(mode, "rowhammer") == 0) {
        function_pointer = hash_row_hammer_test;
    } else if (strcmp(mode, "bruteforce") == 0) {
        function_pointer = hash_brute_force_speed_test;
    } else {
        fprintf(stderr, "Invalid mode specified. Accepted mode: replicated, timing, rowhammer, bruteforce, no key size needed\n");
        free(threads);
        free(thread_data);
        return 1;
    }

    printf("Initializing %s Test with %d threads...\n", mode, num_threads);
    for (int i = 0; i < num_threads; i++) {
        initialize_thread_data(&thread_data[i], i);
        if (pthread_create(&threads[i], NULL, function_pointer, &thread_data[i])) {
            fprintf(stderr, "Failed to create thread %d\n", i);
        }
    }

    FILE *fp = fopen("output_data.txt", "w");
    if (!fp) {
        fprintf(stderr, "Failed to create the output file.\n");
        for (int i = 0; i < num_threads; i++) {
            pthread_cancel(threads[i]); 
            pthread_join(threads[i], NULL);
        }
        free(threads);
        free(thread_data);
        return 1;
    }

    for (int i = 0; i < num_threads; i++) {
        if (pthread_join(threads[i], NULL)) {
            fprintf(stderr, "Failed to join thread %d\n", i);
        }
        fprintf(fp, "Thread ID: %d, Success: %d, Hash Output: %s\n", thread_data[i].thread_id, thread_data[i].success, thread_data[i].hash_output);
    }

    time_t current_time = time(NULL);
    fprintf(fp, "File generated on: %s\n", ctime(&current_time));

    fclose(fp);
    free(threads);
    for (int i = 0; i < num_threads; i++) {
        free(thread_data[i].data);
        free(thread_data[i].hash_output); 
    }
    free(thread_data);
    return 0;
}