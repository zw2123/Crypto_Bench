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

#define DATA_SIZE (1024 * 1024 * 1024) // 1 GB for more realistic testing

typedef struct {
    int thread_id;
    unsigned char *data;
    unsigned char key[32];
    unsigned char iv[16];
    int key_size;
    int data_len;
    int encrypted_len;
    int success;
    char *attack_type;
    int introduce_fault;
    struct timespec start_time, end_time;
    struct rusage usage_start, usage_end;
    EVP_CIPHER_CTX *ctx;
    char result_string[512];
} ThreadData;

void handleErrors(const char* error) {
    fprintf(stderr, "Error: %s\n", error);
    exit(1);
}

void opensslHandleErrors() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

void inject_selective_fault(unsigned char *arr, int pos) {
    arr[pos / 8] ^= (1 << (pos % 8));
}

EVP_CIPHER_CTX* initialize_aes_ctr_context(unsigned char *key, unsigned char *iv, int key_size) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) opensslHandleErrors();

    const EVP_CIPHER *cipher_type = (key_size == 256) ? EVP_aes_256_ctr() : EVP_aes_128_ctr();
    if (1 != EVP_CipherInit_ex(ctx, cipher_type, NULL, key, iv, 1)) {
        EVP_CIPHER_CTX_free(ctx);
        opensslHandleErrors();
    }

    return ctx;
}

void aes_ctr_encrypt_decrypt(EVP_CIPHER_CTX *ctx, unsigned char *input, unsigned char *output, int length) {
    int len;
    if (!EVP_CipherUpdate(ctx, output, &len, input, length) || len != length) {
        EVP_CIPHER_CTX_free(ctx);
        opensslHandleErrors();
    }
}

void initialize_thread_data(ThreadData *data, const char *attack, int fault, int thread_id, int key_size) {
    data->thread_id = thread_id;
    data->data = (unsigned char*)malloc(DATA_SIZE);
    if (!data->data) handleErrors("Memory allocation failed for data buffer");

    // Fill the data buffer with a pattern or random data
    for (int i = 0; i < DATA_SIZE; i++) {
        data->data[i] = (unsigned char)(i % 256);  // Simple pattern: byte values 0-255 repeating
    }

    data->key_size = key_size;
    if (!RAND_bytes(data->key, key_size / 8)) {
        fprintf(stderr, "Failed to generate random key.\n");
        handleErrors("Failed to generate random key.");
    }
    if (!RAND_bytes(data->iv, sizeof(data->iv))) {
        fprintf(stderr, "Failed to generate random IV.\n");
        handleErrors("Failed to generate random IV.");
    }

    if (fault) {
        inject_selective_fault(data->key, 0);  // Inject fault at the first bit of the key
        inject_selective_fault(data->iv, 7);   // Inject fault at the eighth bit of the IV
    }

    data->ctx = initialize_aes_ctr_context(data->key, data->iv, data->key_size);
    data->data_len = DATA_SIZE;
    data->success = 1;
    data->attack_type = strdup(attack);
    data->introduce_fault = fault;
}

void *brute_force_speed_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char *decrypted_text = malloc(data->data_len);
    unsigned char test_key[32];
    unsigned long long num_keys_tested = 0;
    int test_duration_seconds = 15;
    int warmup_duration_seconds = 5;  // Duration for warm-up phase
    time_t end_time, start_time, warmup_end_time;

    // Hardware capabilities (keys per second)
    double cpu_keys_per_second = 1e8;  // 100 million keys/s
    double gpu_keys_per_second = 1e10;  // 10 billion keys/s
    double asic_keys_per_second = 1e11; // 100 billion keys/s

    if (!decrypted_text) {
        fprintf(stderr, "Memory allocation error in brute_force_speed_test\n");
        data->success = 0;
        return NULL;
    }

    memset(test_key, 0, sizeof(test_key));  // Start with a zero key
    memcpy(decrypted_text, data->data, data->data_len);  // Copy ciphertext into decrypted_text

    EVP_CIPHER_CTX *ctx = NULL;

    // Warm-up phase
    start_time = time(NULL);
    do {
        ctx = initialize_aes_ctr_context(test_key, data->iv, data->key_size);
        if (!ctx) {
            fprintf(stderr, "AES CTR context initialization failed in brute force test\n");
            continue;
        }
        aes_ctr_encrypt_decrypt(ctx, data->data, decrypted_text, data->data_len);
        EVP_CIPHER_CTX_free(ctx); // Clean up the context after each attempt

        for (int i = 0; i < data->key_size / 8; i++) {
            if (++test_key[i]) break;  // Increment key byte; if not wrapped around, stop incrementing
        }
        warmup_end_time = time(NULL);
    } while (difftime(warmup_end_time, start_time) < warmup_duration_seconds);

    // Reset test key after warm-up
    memset(test_key, 0, sizeof(test_key));

    // Actual test phase
    start_time = time(NULL);  // Reset start time for the actual measurement
    do {
        ctx = initialize_aes_ctr_context(test_key, data->iv, data->key_size);
        if (!ctx) {
            fprintf(stderr, "AES CTR context initialization failed in brute force test\n");
            continue;
        }
        aes_ctr_encrypt_decrypt(ctx, data->data, decrypted_text, data->data_len);
        num_keys_tested++;

        EVP_CIPHER_CTX_free(ctx); // Clean up the context after each attempt

        for (int i = 0; i < data->key_size / 8; i++) {
            if (++test_key[i]) break;  // Increment key byte; if not wrapped around, stop incrementing
        }

        end_time = time(NULL);
    } while (difftime(end_time, start_time) < test_duration_seconds);

    double keys_per_second = num_keys_tested / difftime(end_time, start_time);
    double years_to_test_all_keys = pow(2, data->key_size) / (keys_per_second * 3600 * 24 * 365);

    // Display the test results
    printf("Brute force speed test by Thread %d:\n", data->thread_id);
    printf("Keys tested per second: %.2f\n", keys_per_second);
    printf("Estimated years to test all keys: %.2f years\n", years_to_test_all_keys);

    // Comparison with state-of-the-art hardware
    printf("CPU estimate: %.2e years\n", pow(2, data->key_size) / (cpu_keys_per_second * 3600 * 24 * 365));
    printf("GPU estimate: %.2e years\n", pow(2, data->key_size) / (gpu_keys_per_second * 3600 * 24 * 365));
    printf("ASIC estimate: %.2e years\n", pow(2, data->key_size) / (asic_keys_per_second * 3600 * 24 * 365));

    free(decrypted_text);
    data->success = 1;
    return NULL;
}

void *rowhammer_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char *outputBeforeFault = malloc(data->data_len);
    unsigned char *outputAfterFault = malloc(data->data_len);

    if (!outputBeforeFault || !outputAfterFault) {
        fprintf(stderr, "Memory allocation error in rowhammer_test\n");
        data->success = 0; // Indicate failure
        if (outputBeforeFault) free(outputBeforeFault);
        if (outputAfterFault) free(outputAfterFault);
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = initialize_aes_ctr_context(data->key, data->iv, data->key_size);
    if (!ctx) {
        fprintf(stderr, "Failed to initialize AES context\n");
        free(outputBeforeFault);
        free(outputAfterFault);
        return NULL;
    }

    // Encrypt data before injecting fault
    aes_ctr_encrypt_decrypt(ctx, data->data, outputBeforeFault, data->data_len);

    // Inject fault
    inject_selective_fault(data->data, data->data_len - 1);  // Inject a fault at the last bit of the data

    // Re-initialize context for a fair comparison
    EVP_CIPHER_CTX_free(ctx);
    ctx = initialize_aes_ctr_context(data->key, data->iv, data->key_size);
    if (!ctx) {
        fprintf(stderr, "Failed to re-initialize AES context after fault injection\n");
        free(outputBeforeFault);
        free(outputAfterFault);
        return NULL;
    }

    // Encrypt data after injecting fault
    aes_ctr_encrypt_decrypt(ctx, data->data, outputAfterFault, data->data_len);

    // Compare the outputs and summarize the result
    int result = memcmp(outputBeforeFault, outputAfterFault, data->data_len);
    printf("Rowhammer Test for Thread %d completed. ", data->thread_id);
    if (result != 0) {
        printf("Fault injection altered the encryption output.\n");
    } else {
        printf("No change in output despite fault injection.\n");
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    free(outputBeforeFault);
    free(outputAfterFault);

    data->success = 1;
    return NULL;
}


void *timing_analysis(void *arg) {
    ThreadData *data = (ThreadData *)arg;

    int num_trials = 20;
    double *times = (double *)malloc(num_trials * sizeof(double));
    if (!times) {
        fprintf(stderr, "Failed to allocate memory for timing data\n");
        data->success = 0;
        return NULL;
    }

    double sum = 0.0, mean, standard_deviation = 0.0;

    // Initialize the AES CTR context
    EVP_CIPHER_CTX *ctx = initialize_aes_ctr_context(data->key, data->iv, data->key_size);
    if (!ctx) {
        fprintf(stderr, "Failed to initialize AES CTR context\n");
        free(times);
        return NULL;
    }

    for (int i = 0; i < num_trials; i++) {
        unsigned char *output = malloc(data->data_len); // Allocate memory for the output
        if (!output) {
            fprintf(stderr, "Failed to allocate memory for encryption output\n");
            EVP_CIPHER_CTX_free(ctx);
            free(times);
            data->success = 0;
            return NULL;
        }

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        aes_ctr_encrypt_decrypt(ctx, data->data, output, data->data_len);
        clock_gettime(CLOCK_MONOTONIC, &end);

        times[i] = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        sum += times[i];

        free(output); // Free the output buffer after each trial
    }

    mean = sum / num_trials;

    for (int i = 0; i < num_trials; i++) {
        standard_deviation += pow(times[i] - mean, 2);
    }

    standard_deviation = sqrt(standard_deviation / num_trials);
    double cv = (standard_deviation / mean) * 100;

    printf("Timing Analysis Results:\n");
    printf("Mean Time: %.9f seconds, Standard Deviation: %.9f seconds, CV: %.2f%%\n", mean, standard_deviation, cv);

    if (cv < 1.0) {
        printf("Low risk of timing side-channel leakage.\n");
    } else if (cv < 5.0) {
        printf("Moderate risk of timing side-channel leakage. Consider further investigation.\n");
    } else {
        printf("High risk of timing side-channel leakage. Immediate action recommended.\n");
    }

    EVP_CIPHER_CTX_free(ctx); // Clean up the AES context
    free(times);
    data->success = 1;
    return NULL;
}

void *replicated_execution(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char *output1 = malloc(data->data_len);
    unsigned char *output2 = malloc(data->data_len);

    if (!output1 || !output2) {
        fprintf(stderr, "Memory allocation error in replicated_execution\n");
        data->success = 0; // Indicate failure
        return NULL;
    }

    aes_ctr_encrypt_decrypt(data->ctx, data->data, output1, data->data_len);
    aes_ctr_encrypt_decrypt(data->ctx, data->data, output2, data->data_len);

    if (memcmp(output1, output2, data->data_len) != 0) {
        fprintf(stderr, "Discrepancy detected in outputs!\n");
        data->success = 0;
    } else {
        data->success = 1;
    }

    free(output1);
    free(output2);
    return NULL;
}

void *differential_cryptanalysis_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char *output1 = malloc(data->data_len);
    unsigned char *output2 = malloc(data->data_len);
    unsigned char *modified_data = malloc(data->data_len);

    if (!output1 || !output2 || !modified_data) {
        fprintf(stderr, "Memory allocation error in differential_cryptanalysis_test\n");
        data->success = 0;
        free(output1);
        free(output2);
        free(modified_data);
        return NULL;
    }

    // Initialize the AES context
    EVP_CIPHER_CTX *ctx = initialize_aes_ctr_context(data->key, data->iv, data->key_size);
    if (!ctx) {
        free(output1);
        free(output2);
        free(modified_data);
        return NULL;
    }

    // Create a slightly modified version of the original data
    memcpy(modified_data, data->data, data->data_len);
    modified_data[0] ^= 0x01;  // Flip the first bit

    // Encrypt both original and modified data
    aes_ctr_encrypt_decrypt(ctx, data->data, output1, data->data_len);
    aes_ctr_encrypt_decrypt(ctx, modified_data, output2, data->data_len);

    // Compare outputs and summarize the result
    int differences = 0;
    for (int i = 0; i < data->data_len; i++) {
        if (output1[i] != output2[i]) differences++;
    }

    printf("Differential Cryptanalysis Test for Thread %d completed. Differences: %d\n", data->thread_id, differences);

    EVP_CIPHER_CTX_free(ctx);
    free(output1);
    free(output2);
    free(modified_data);
    data->success = 1;
    return NULL;
}

void *linear_cryptanalysis_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char *output = malloc(data->data_len);

    if (!output) {
        fprintf(stderr, "Memory allocation error in linear_cryptanalysis_test\n");
        data->success = 0;
        return NULL;
    }

    // Initialize the AES context
    EVP_CIPHER_CTX *ctx = initialize_aes_ctr_context(data->key, data->iv, data->key_size);
    if (!ctx) {
        free(output);
        return NULL;
    }

    // Encrypt the data
    aes_ctr_encrypt_decrypt(ctx, data->data, output, data->data_len);

    // Check for a simple linear relation: sum of bits at even positions
    int plaintext_bit_sum = 0, ciphertext_bit_sum = 0;
    for (size_t i = 0; i < data->data_len; i++) {
        for (int j = 0; j < 8; j += 2) { // Only check even bit positions
            plaintext_bit_sum += (data->data[i] >> j) & 1;
            ciphertext_bit_sum += (output[i] >> j) & 1;
        }
    }

    printf("Linear Cryptanalysis Test for Thread %d completed. Plaintext Bit Sum: %d, Ciphertext Bit Sum: %d\n",
           data->thread_id, plaintext_bit_sum, ciphertext_bit_sum);

    EVP_CIPHER_CTX_free(ctx);
    free(output);
    data->success = 1;
    return NULL;
}

int get_num_cpu_cores() {
    return sysconf(_SC_NPROCESSORS_ONLN);
}

void *replicated_execution(void *arg);
void *timing_analysis(void *arg);
void *rowhammer_test(void *arg);
void *differential_cryptanalysis_test(void *arg);
void *linear_cryptanalysis_test(void *arg);
void *brute_force_speed_test(void *arg);

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <128|256> <rowhammer|timing|replicated|differential|linear|brute_force>\n", argv[0]);
        return 1;
    }

    int key_size = atoi(argv[1]);
    if (key_size != 128 && key_size != 256) {
        fprintf(stderr, "Invalid key size. Please choose 128 or 256.\n");
        return 1;
    }

    char *mode = argv[2];
    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    ThreadData *thread_data = calloc(num_threads, sizeof(ThreadData));

    void *(*function_pointer)(void *) = NULL;

    // Mapping function pointers based on the mode
    if (strcmp(mode, "replicated") == 0) {
        function_pointer = replicated_execution;
    } else if (strcmp(mode, "timing") == 0) {
        function_pointer = timing_analysis;
    } else if (strcmp(mode, "rowhammer") == 0) {
        function_pointer = rowhammer_test;
    } else if (strcmp(mode, "differential") == 0) {
        function_pointer = differential_cryptanalysis_test;
    } else if (strcmp(mode, "linear") == 0) {
        function_pointer = linear_cryptanalysis_test;
    } else if (strcmp(mode, "bruteforce") == 0) {
        function_pointer = brute_force_speed_test;
    } else {
        fprintf(stderr, "Invalid mode specified.\n");
        free(threads);
        free(thread_data);
        return 1;
    }

    printf("Initializing %s Test with %d threads...\n", mode, num_threads);
    for (int i = 0; i < num_threads; i++) {
        initialize_thread_data(&thread_data[i], mode, 1, i, key_size);
        pthread_create(&threads[i], NULL, function_pointer, &thread_data[i]);
    }

    FILE *fp = fopen("output_data.txt", "w");
    if (!fp) {
        fprintf(stderr, "Failed to create the output file.\n");
        free(threads);
        free(thread_data);
        return 1;
    }

    // Wait for all threads to complete
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);

        // Write the results from each thread into the file
        fprintf(fp, "Thread ID: %d\n", thread_data[i].thread_id);
        fprintf(fp, "Key: ");
        for (int k = 0; k < key_size / 8; k++) {
            fprintf(fp, "%02x", thread_data[i].key[k]);
        }
        fprintf(fp, "\nIV: ");
        for (int k = 0; k < 16; k++) {
            fprintf(fp, "%02x", thread_data[i].iv[k]);
        }
        fprintf(fp, "\nCiphertext: ");
        for (int k = 0; k < thread_data[i].data_len && k < 256; k++) {  // Display only the first 256 bytes
            fprintf(fp, "%02x", thread_data[i].data[k]);
        }
        fprintf(fp, "\n\n");
    }

    // Get and write the current time
    time_t current_time = time(NULL);
    fprintf(fp, "File generated on: %s\n", ctime(&current_time));

    fclose(fp);
    free(threads);
    free(thread_data);
    return 0;
}