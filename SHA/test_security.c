/* How does this work:
The code performs several types of security and performance tests for hashing using OpenSSL, specifically targeting SHA-1 or SHA-256:

1.Timing Analysis: Measures the time taken to perform hash operations over multiple trials to calculate average times and detect 
  potential timing vulnerabilities.

2.Replicated Execution: Verifies the consistency of the hash output by hashing the same data multiple times and checking if the results
  are identical.

3.Linear Cryptanalysis Test: Assesses the susceptibility to linear cryptanalysis by comparing the sums of bits at each position in the 
  input and the hash output.

4.Differential Cryptanalysis Test: Observes how changes in the input affect the hash output by modifying the input slightly (e.g., 
  flipping a bit) and comparing the resultant hashes.

5.Rowhammer Test: Simulates fault attacks (like those induced by the Rowhammer bug) to see if they can alter the hash output, thereby 
  assessing the hash function's resilience to physical fault attacks.

6.Brute Force Preimage Test: Attempts to find a preimage by randomly generating input data and hashing it until the hash matches a predefined 
  target hash, measuring the effort required in terms of time and number of attempts.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>  
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <time.h>
#include <math.h> 


#define DATA_SIZE (1024 * 1024 * 50) // 50 MB data blocks for hashing

typedef struct {
    int thread_id;
    unsigned char *data;
    int data_len;
    char *hash_type;
    struct timespec start_time, end_time;
} ThreadData;

void handleErrors(const char* error) {
    fprintf(stderr, "Error: %s\n", error);
    exit(1);
}

const EVP_MD *select_hash_function(const char *type) {
    if (strcmp(type, "1") == 0) {
        return EVP_sha1();
    } else if (strcmp(type, "256") == 0) {
        return EVP_sha256();
    } else {
        handleErrors("Unsupported hash type");
        return NULL; // This return will never be reached; just to silence compiler warnings
    }
}

void perform_hash(EVP_MD_CTX *ctx, unsigned char *data, size_t data_len, unsigned char *md, unsigned int *md_len) {
    if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) handleErrors("Hash initialization failed");
    if (1 != EVP_DigestUpdate(ctx, data, data_len)) handleErrors("Hash update failed");
    if (1 != EVP_DigestFinal_ex(ctx, md, md_len)) handleErrors("Hash finalization failed");
}

void *timing_analysis(void *arg) {
    ThreadData *data = (ThreadData *)arg;

    const EVP_MD *md = select_hash_function(data->hash_type);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) handleErrors("Failed to create MD context");

    int num_trials = 20;
    double times[num_trials], sum = 0.0, mean, standard_deviation = 0.0;
    
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    for (int i = 0; i < num_trials; i++) {
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        perform_hash(ctx, data->data, data->data_len, md_value, &md_len);
        clock_gettime(CLOCK_MONOTONIC, &end);
        times[i] = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        sum += times[i];
    }

    mean = sum / num_trials;
    for (int i = 0; i < num_trials; i++) {
        standard_deviation += pow(times[i] - mean, 2);
    }
    standard_deviation = sqrt(standard_deviation / num_trials);
    double cv = (standard_deviation / mean) * 100;

    printf("Timing Analysis Results for Thread %d:\n", data->thread_id);
    printf("Mean Time: %.9f seconds, Standard Deviation: %.9f seconds, CV: %.2f%%\n", mean, standard_deviation, cv);

    EVP_MD_CTX_free(ctx);
    return NULL;
}

void *replicated_execution(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    const EVP_MD *md = select_hash_function(data->hash_type);
    EVP_MD_CTX *ctx1 = EVP_MD_CTX_new();
    EVP_MD_CTX *ctx2 = EVP_MD_CTX_new();
    unsigned char *output1 = malloc(EVP_MD_size(md));
    unsigned char *output2 = malloc(EVP_MD_size(md));
    unsigned int md_len1, md_len2;

    if (!output1 || !output2 || !ctx1 || !ctx2) {
        fprintf(stderr, "Memory allocation error in replicated_execution\n");
        if (output1) free(output1);
        if (output2) free(output2);
        if (ctx1) EVP_MD_CTX_free(ctx1);
        if (ctx2) EVP_MD_CTX_free(ctx2);
        return NULL;
    }

    // Perform the first hash
    if (!EVP_DigestInit_ex(ctx1, md, NULL) ||
        !EVP_DigestUpdate(ctx1, data->data, data->data_len) ||
        !EVP_DigestFinal_ex(ctx1, output1, &md_len1)) {
        fprintf(stderr, "Error in hashing during replicated execution (first pass)\n");
        EVP_MD_CTX_free(ctx1);
        EVP_MD_CTX_free(ctx2);
        free(output1);
        free(output2);
        return NULL;
    }

    // Perform the second hash
    if (!EVP_DigestInit_ex(ctx2, md, NULL) ||
        !EVP_DigestUpdate(ctx2, data->data, data->data_len) ||
        !EVP_DigestFinal_ex(ctx2, output2, &md_len2)) {
        fprintf(stderr, "Error in hashing during replicated execution (second pass)\n");
        EVP_MD_CTX_free(ctx1);
        EVP_MD_CTX_free(ctx2);
        free(output1);
        free(output2);
        return NULL;
    }

    // Compare the outputs
    if (memcmp(output1, output2, md_len1) != 0) {
        fprintf(stderr, "Discrepancy detected in outputs!\n");
    } else {
        printf("Replication test for Thread %d completed successfully. No discrepancies found.\n", data->thread_id);
    }

    EVP_MD_CTX_free(ctx1);
    EVP_MD_CTX_free(ctx2);
    free(output1);
    free(output2);
    return NULL;
}


void *linear_cryptanalysis_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char *output = malloc(EVP_MAX_MD_SIZE);
    unsigned int md_len;

    if (!output) {
        fprintf(stderr, "Memory allocation error in linear_cryptanalysis_test\n");
        return NULL;
    }

    const EVP_MD *md = select_hash_function(data->hash_type);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        free(output);
        return NULL;
    }

    // Hash the data
    perform_hash(ctx, data->data, data->data_len, output, &md_len);

    // Check for linear relation: sum of bits at each position
    int input_bit_sum = 0, output_bit_sum = 0;
    for (size_t i = 0; i < data->data_len; i++) {
        for (int j = 0; j < 8; j++) { // Check every bit position in input
            input_bit_sum += (data->data[i] >> j) & 1;
        }
    }
    for (size_t i = 0; i < md_len; i++) {
        for (int j = 0; j < 8; j++) { // Check every bit position in output hash
            output_bit_sum += (output[i] >> j) & 1;
        }
    }

    printf("Linear Cryptanalysis Test for Thread %d completed. Input Bit Sum: %d, Output Bit Sum: %d\n",
           data->thread_id, input_bit_sum, output_bit_sum);

    EVP_MD_CTX_free(ctx);
    free(output);
    return NULL;
}

void *differential_cryptanalysis_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;

    const EVP_MD *md = select_hash_function(data->hash_type);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) handleErrors("Failed to create MD context");

    unsigned char md_original[EVP_MAX_MD_SIZE], md_modified[EVP_MAX_MD_SIZE];
    unsigned int md_len_original, md_len_modified;
    
    unsigned char *modified_data = malloc(data->data_len);
    memcpy(modified_data, data->data, data->data_len);
    modified_data[0] ^= 0x01;  // Flip the first bit

    perform_hash(ctx, data->data, data->data_len, md_original, &md_len_original);
    perform_hash(ctx, modified_data, data->data_len, md_modified, &md_len_modified);

    int differences = 0;
    for (unsigned int i = 0; i < md_len_original; i++) {
        if (md_original[i] != md_modified[i]) differences++;
    }

    printf("Differential Cryptanalysis Test for Thread %d completed. Differences: %d\n", data->thread_id, differences);

    free(modified_data);
    EVP_MD_CTX_free(ctx);
    return NULL;
}

void inject_selective_fault(unsigned char *data, size_t len) {
    // Flip a random bit in the data
    size_t byte_index = rand() % len;
    size_t bit_index = rand() % 8;
    data[byte_index] ^= (1 << bit_index);
}

void *rowhammer_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    const EVP_MD *md = select_hash_function(data->hash_type);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char *outputBeforeFault = malloc(EVP_MD_size(md));
    unsigned char *outputAfterFault = malloc(EVP_MD_size(md));
    unsigned int md_len;

    if (!outputBeforeFault || !outputAfterFault || !ctx) {
        fprintf(stderr, "Memory allocation or context initialization error in rowhammer_test\n");
        if (outputBeforeFault) free(outputBeforeFault);
        if (outputAfterFault) free(outputAfterFault);
        if (ctx) EVP_MD_CTX_free(ctx);
        return NULL;
    }

    // Hash data before injecting fault
    perform_hash(ctx, data->data, data->data_len, outputBeforeFault, &md_len);

    // Inject fault
    inject_selective_fault(data->data, data->data_len);  // Inject a fault at a random bit of the data

    // Hash data after injecting fault
    perform_hash(ctx, data->data, data->data_len, outputAfterFault, &md_len);

    // Compare the outputs and summarize the result
    int result = memcmp(outputBeforeFault, outputAfterFault, md_len);
    printf("Rowhammer Test for Thread %d completed. ", data->thread_id);
    if (result != 0) {
        printf("Fault injection altered the hash output.\n");
    } else {
        printf("No change in hash output despite fault injection.\n");
    }

    // Clean up
    EVP_MD_CTX_free(ctx);
    free(outputBeforeFault);
    free(outputAfterFault);

    return NULL;
}

void *brute_force_preimage_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    const EVP_MD *md = select_hash_function(data->hash_type);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) handleErrors("Failed to create MD context");

    unsigned char target_md[EVP_MAX_MD_SIZE], test_md[EVP_MAX_MD_SIZE];
    unsigned int target_md_len, test_md_len;
    unsigned char *test_data = malloc(data->data_len);
    
    // Generate a target hash
    RAND_bytes(data->data, data->data_len); // Random data for target
    perform_hash(ctx, data->data, data->data_len, target_md, &target_md_len);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    unsigned long attempts = 0;
    int found = 0;

    // Shorten the brute force test duration for practical testing
    double duration = 0;
    int test_duration_seconds = 60; // Run for only 1 minute for initial testing

    while (!found && duration < test_duration_seconds) {
        RAND_bytes(test_data, data->data_len);
        perform_hash(ctx, test_data, data->data_len, test_md, &test_md_len);
        attempts++;
        if (memcmp(target_md, test_md, target_md_len) == 0) {
            found = 1;
        }

        struct timespec check_time;
        clock_gettime(CLOCK_MONOTONIC, &check_time);
        duration = (check_time.tv_sec - start.tv_sec) + (check_time.tv_nsec - start.tv_nsec) / 1e9;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double total_duration = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("Brute Force Preimage Test for Thread %d completed. Found: %d, Attempts: %lu, Total Duration: %.2f seconds\n",
           data->thread_id, found, attempts, total_duration);
    printf("Hashes per second: %.2f\n", attempts / total_duration);

    // Extrapolate to estimate the time required to potentially find a preimage
    double hashes_needed = pow(2, strcmp(data->hash_type, "1") == 0 ? 160 : 256);// SHA-1 is 160 bits, SHA-256 is 256 bits
    double years_to_break = (hashes_needed / (attempts / total_duration)) / (3600 * 24 * 365);

    printf("Estimated years to test all possible preimages: %.2e years\n", years_to_break);

    free(test_data);
    EVP_MD_CTX_free(ctx);
    return NULL;
}


int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <1|256> <timing|differential|brute_force|rowhammer|linear|replicated>\n", argv[0]);
        return 1;
    }

    char *hash_type = argv[1];
    char *test_type = argv[2];

    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    ThreadData *thread_data = malloc(num_threads * sizeof(ThreadData));

    if (!threads || !thread_data) {
        fprintf(stderr, "Failed to allocate memory for threads or thread data\n");
        free(threads);
        free(thread_data);
        return 1;
    }

    void *(*function_pointer)(void *) = NULL;

    if (strcmp(test_type, "timing") == 0) {
        function_pointer = timing_analysis;
    } else if (strcmp(test_type, "differential") == 0) {
        function_pointer = differential_cryptanalysis_test;
    } else if (strcmp(test_type, "bruteforce") == 0) {
        function_pointer = brute_force_preimage_test;
    } else if (strcmp(test_type, "rowhammer") == 0) {
        function_pointer = rowhammer_test;
    } else if (strcmp(test_type, "linear") == 0) {
        function_pointer = linear_cryptanalysis_test;
    } else if (strcmp(test_type, "replicated") == 0) {
        function_pointer = replicated_execution;
    } else {
        fprintf(stderr, "Invalid test type specified.\n");
        free(threads);
        free(thread_data);
        return 1;
    }

    for (int i = 0; i < num_threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].data_len = DATA_SIZE;
        thread_data[i].data = (unsigned char*)malloc(DATA_SIZE);
        if (!thread_data[i].data) {
            fprintf(stderr, "Failed to allocate memory for data in thread %d\n", i);
            for (int j = 0; j < i; j++) { // Free already allocated data in case of failure
                free(thread_data[j].data);
            }
            free(threads);
            free(thread_data);
            return 1;
        }
        RAND_bytes(thread_data[i].data, DATA_SIZE); // Fill the data buffer with random data
        thread_data[i].hash_type = hash_type;

        if (pthread_create(&threads[i], NULL, function_pointer, &thread_data[i]) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            free(thread_data[i].data); // Free the data allocated for this thread
            for (int j = 0; j < i; j++) { // Also free the data and join created threads
                pthread_join(threads[j], NULL);
                free(thread_data[j].data);
            }
            free(threads);
            free(thread_data);
            return 1;
        }
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
        free(thread_data[i].data);
    }

    free(threads);
    free(thread_data);
    return 0;
}