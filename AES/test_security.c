/*How does this work:
This code contains six types of tests designed to evaluate the resistance of AES against usual hardware vulnerabilities.

1.Brute Force Speed Test: This test measures the speed of attempting different AES keys. It involves repeatedly initializing 
  the encryption context and encrypting a fixed data set with incrementally changing keys. The test calculates how many keys 
  can be tried per second and extrapolates this to estimate how long it would take to test all possible keys.

2.Rowhammer Test: Simulates a fault attack by altering data bits using the inject_selective_fault function. It encrypts the 
  data, introduces faults, and then encrypts it again to see if the faults change the output, indicating vulnerability.

3.Timing Analysis: Measures the encryption time for multiple trials to identify any significant variations that might indicate a 
  timing side-channel vulnerability. It calculates the mean, standard deviation, and coefficient of variation of the encryption times.

4.Replicated Execution Test: Checks for consistency in AES encryption output by encrypting the same data twice under identical 
  conditions and comparing the outputs to ensure they match, which verifies deterministic behavior.

5.Differential Cryptanalysis Test: Encrypts a plaintext and a slightly modified version of it (by flipping a bit) to observe how the 
  change affects the ciphertext. The test counts the number of differing bits between the two ciphertexts to assess susceptibility to 
  differential attacks.

6.Linear Cryptanalysis Test: Encrypts data and then analyzes the correlation between plaintext bits and ciphertext bits across multiple
  positions, looking for any linear patterns that could be used to break the encryption.*/

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
#include <float.h>  

#define DATA_SIZE (1024 * 1024 * 50) 
#define ENERGY_PER_BIT_TRANSITION 0.0001  
#define ITERATIONS 10
#define WARMUP_ROUNDS 100
#define MEASURE_ROUNDS 1000

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
    double power_consumption;
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

    
    for (int i = 0; i < DATA_SIZE; i++) {
        data->data[i] = (unsigned char)(i % 256);  
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

int hamming_weight(unsigned char byte) {
    int weight = 0;
    while (byte) {
        weight += byte & 1;
        byte >>= 1;
    }
    return weight;
}

void *power_analysis_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char block[16];
    int out_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx || !EVP_CipherInit_ex(ctx, (data->key_size == 256) ? EVP_aes_256_ctr() : EVP_aes_128_ctr(), NULL, data->key, data->iv, 1)) {
        fprintf(stderr, "EVP_CipherInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        data->success = 0;
        return NULL;
    }

    double total_energy_consumption = 0.0;
    double min_power = DBL_MAX, max_power = 0.0;

    for (int i = 0; i < data->data_len; i += 16) {
    int len = (data->data_len - i < 16) ? data->data_len - i : 16;
    if (!EVP_CipherUpdate(ctx, block, &out_len, data->data + i, len)) {
        fprintf(stderr, "EVP_CipherUpdate failed\n");
        continue;
    }
    printf("Processed length: %d\n", out_len);

    for (int j = 0; j < out_len; j++) {
        double byte_power = hamming_weight(block[j]) * ENERGY_PER_BIT_TRANSITION;
        printf("Byte power for byte %d: %.2f\n", j, byte_power);
        total_energy_consumption += byte_power;
        if (byte_power < min_power) min_power = byte_power;
        if (byte_power > max_power) max_power = byte_power;
    }
}

    if (min_power == DBL_MAX) min_power = 0;

    EVP_CIPHER_CTX_free(ctx);

    printf("Thread %d:\nTotal Power consumption calculated: %.2f picojoules for AES-%d\n", data->thread_id, total_energy_consumption, data->key_size);
    
    data->power_consumption = total_energy_consumption;
    data->success = 1;
    return NULL;
}

void *cache_timing_analysis(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char block[16];
    int out_len = 0;
    struct timespec start, end;
    double times[ITERATIONS];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx || !EVP_CipherInit_ex(ctx, (data->key_size == 256) ? EVP_aes_256_ctr() : EVP_aes_128_ctr(), NULL, data->key, data->iv, 1)) {
        fprintf(stderr, "EVP_CipherInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        data->success = 0;
        return NULL;
    }

    // Warm up the cache
    for (int i = 0; i < 10; i++) {
        EVP_CipherUpdate(ctx, block, &out_len, data->data, sizeof(block));
    }

    // Measure encryption time repeatedly
    for (int i = 0; i < ITERATIONS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        EVP_CipherUpdate(ctx, block, &out_len, data->data, sizeof(block));
        clock_gettime(CLOCK_MONOTONIC, &end);
        times[i] = (end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec); // Time in nanoseconds
    }

    EVP_CIPHER_CTX_free(ctx);

    double min_time = DBL_MAX, max_time = 0.0;
    for (int i = 0; i < ITERATIONS; i++) {
        if (times[i] < min_time) min_time = times[i];
        if (times[i] > max_time) max_time = times[i];
    }

    printf("Thread %d:\nMinimum Time: %.2f ns, Maximum Time: %.2f ns\n", data->thread_id, min_time, max_time);
    printf("Cache Timing Analysis Result: Time variation between min and max encryption times could indicate cache effects and potential side-channel vulnerabilities.\n");

    data->success = 1;
    return NULL;
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

    printf("Brute force speed test by Thread %d:\n", data->thread_id);
    printf("Keys tested per second: %e\n", keys_per_second);
    printf("Estimated years to test all keys: %e years\n", years_to_test_all_keys);

    // Comparison with state-of-the-art hardware
    printf("CPU estimate: %e years\n", pow(2, data->key_size) / (cpu_keys_per_second * 3600 * 24 * 365));
    printf("GPU estimate: %e years\n", pow(2, data->key_size) / (gpu_keys_per_second * 3600 * 24 * 365));
    printf("ASIC estimate: %e years\n", pow(2, data->key_size) / (asic_keys_per_second * 3600 * 24 * 365));

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
        data->success = 0; 
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
    inject_selective_fault(data->data, data->data_len - 1);  

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

    
    EVP_CIPHER_CTX *ctx = initialize_aes_ctr_context(data->key, data->iv, data->key_size);
    if (!ctx) {
        fprintf(stderr, "Failed to initialize AES CTR context\n");
        free(times);
        return NULL;
    }

    for (int i = 0; i < num_trials; i++) {
        unsigned char *output = malloc(data->data_len); 
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

        free(output); 
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

    EVP_CIPHER_CTX_free(ctx); 
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
        free(output1); 
        free(output2);
        return NULL;
    }

    // Encrypt the first set of data
    aes_ctr_encrypt_decrypt(data->ctx, data->data, output1, data->data_len);

    // Reinitialize the context to reset the counter
    EVP_CIPHER_CTX_free(data->ctx);
    data->ctx = initialize_aes_ctr_context(data->key, data->iv, data->key_size);
    if (!data->ctx) {
        fprintf(stderr, "Error reinitializing the encryption context.\n");
        free(output1);
        free(output2);
        data->success = 0;
        return NULL;
    }

    // Encrypt the second set of data
    aes_ctr_encrypt_decrypt(data->ctx, data->data, output2, data->data_len);

    // Compare the results of the two encryption operations
    if (memcmp(output1, output2, data->data_len) != 0) {
        fprintf(stderr, "Discrepancy detected in outputs!\n");
        data->success = 0;
    } else {
        printf("Test successful: No discrepancy detected in outputs.\n");
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

    // Bit-wise analysis across all positions
    int *plaintext_bit_count = calloc(8, sizeof(int));
    int *ciphertext_bit_count = calloc(8, sizeof(int));
    if (!plaintext_bit_count || !ciphertext_bit_count) {
        fprintf(stderr, "Failed to allocate memory for bit counts.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
        free(plaintext_bit_count);
        free(ciphertext_bit_count);
        return NULL;
    }

    for (size_t i = 0; i < data->data_len; i++) {
        for (int j = 0; j < 8; j++) {
            plaintext_bit_count[j] += (data->data[i] >> j) & 1;
            ciphertext_bit_count[j] += (output[i] >> j) & 1;
        }
    }

    printf("Linear Cryptanalysis Test for Thread %d completed.\n", data->thread_id);
    for (int j = 0; j < 8; j++) {
        printf("Bit position %d: Plaintext Bit Sum: %d, Ciphertext Bit Sum: %d\n",
               j, plaintext_bit_count[j], ciphertext_bit_count[j]);
    }

    EVP_CIPHER_CTX_free(ctx);
    free(output);
    free(plaintext_bit_count);
    free(ciphertext_bit_count);
    data->success = 1;
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <128|256> <rowhammer|cache|timing|replicated|differential|linear|bruteforce|power>\n", argv[0]);
        return 1;
    }

    int key_size = atoi(argv[1]);  // First argument for key size
    if (key_size != 128 && key_size != 256) {
        fprintf(stderr, "Invalid key size. Please choose 128 or 256.\n");
        return 1;
    }

    char *mode = argv[2];  // Second argument for mode
    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    ThreadData *thread_data = calloc(num_threads, sizeof(ThreadData));

    void *(*function_pointer)(void *) = NULL;

    if (strcmp(mode, "cache") == 0) {
        function_pointer = cache_timing_analysis;
    }  else if (strcmp(mode, "power") == 0) {
        function_pointer = power_analysis_test;
    } else if (strcmp(mode, "replicated") == 0) {
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
    if (pthread_create(&threads[i], NULL, function_pointer, &thread_data[i]) != 0) {
        fprintf(stderr, "Failed to create thread %d\n", i);
    }
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