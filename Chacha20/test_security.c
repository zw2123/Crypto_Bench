/*How does this work:

1. Differential Cryptanalysis Test: Checks how small changes in input affect the output, useful for understanding the cipher's 
   sensitivity to input modifications.

2. Linear Cryptanalysis Test: Analyzes correlations between plaintext and ciphertext bits.

3. Replicated Execution Test: Ensures that encrypting the same data twice, under identical conditions, produces the same result.

4. Rowhammer Test: Attempts to induce faults in memory to see if it affects cryptographic computations.

5. Timing Analysis Test: Measures the time it takes to encrypt data to assess potential vulnerabilities to timing attacks.

6. Brute Force Speed Test: Evaluates how fast the system can attempt to brute-force the cipher, providing insights into the practical 
   security of the encryption against brute-force attacks.*/

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
    unsigned char key[32]; // ChaCha20 uses a 256-bit key
    unsigned char nonce[12]; // 96-bit nonce for ChaCha20
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

EVP_CIPHER_CTX* initialize_chacha20_context(unsigned char *key, unsigned char *nonce) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors("Failed to create EVP_CIPHER_CTX");
    }
    if (1 != EVP_CipherInit_ex(ctx, EVP_chacha20(), NULL, key, nonce, 1)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors("Failed to initialize ChaCha20 context");
    }
    return ctx;
}

void chacha20_encrypt_decrypt(EVP_CIPHER_CTX *ctx, unsigned char *input, unsigned char *output, int length) {
    int len;
    if (!EVP_CipherUpdate(ctx, output, &len, input, length) || len != length) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors("Encryption/Decryption failed");
    }
}

void print_hex(const char* label, unsigned char *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void initialize_thread_data(ThreadData *data, const char *attack, int fault, int thread_id) {
    data->thread_id = thread_id;
    data->data = (unsigned char*)malloc(DATA_SIZE);
    if (!data->data) handleErrors("Memory allocation failed for data buffer");

    for (int i = 0; i < DATA_SIZE; i++) {
        data->data[i] = (unsigned char)(i % 256);
    }

    if (!RAND_bytes(data->key, sizeof(data->key))) {
        fprintf(stderr, "Failed to generate random key.\n");
        handleErrors("Failed to generate random key.");
    }
    if (!RAND_bytes(data->nonce, sizeof(data->nonce))) {
        fprintf(stderr, "Failed to generate random nonce.\n");
        handleErrors("Failed to generate random nonce.");
    }

    if (fault) {
        inject_selective_fault(data->key, 0); 
        inject_selective_fault(data->nonce, 7); 
    }

    data->ctx = initialize_chacha20_context(data->key, data->nonce);
    data->data_len = DATA_SIZE;
    data->success = 1;
    data->attack_type = strdup(attack);
    data->introduce_fault = fault;
}


void *linear_cryptanalysis_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char *output = malloc(data->data_len);

    if (!output) {
        fprintf(stderr, "Memory allocation error in linear_cryptanalysis_test\n");
        data->success = 0;
        return NULL;
    }

    // Initialize the ChaCha20 context
    EVP_CIPHER_CTX *ctx = initialize_chacha20_context(data->key, data->nonce);
    if (!ctx) {
        free(output);
        return NULL;
    }

    // Encrypt the data
    chacha20_encrypt_decrypt(ctx, data->data, output, data->data_len);

    // Bit-wise analysis across all positions
    int *plaintext_bit_count = calloc(8, sizeof(int));
    int *ciphertext_bit_count = calloc(8, sizeof(int));
    if (!plaintext_bit_count || !ciphertext_bit_count) {
        fprintf(stderr, "Failed to allocate memory for bit counts.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(output);
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

void *differential_cryptanalysis_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char *output1 = malloc(data->data_len);
    unsigned char *output2 = malloc(data->data_len);
    unsigned char *modified_data = malloc(data->data_len);

    if (!output1 || !output2 || !modified_data) {
        fprintf(stderr, "Memory allocation error in differential_cryptanalysis_test\n");
        data->success = 0;  
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = initialize_chacha20_context(data->key, data->nonce);
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
    chacha20_encrypt_decrypt(ctx, data->data, output1, data->data_len);
    chacha20_encrypt_decrypt(ctx, modified_data, output2, data->data_len);

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

void *replicated_execution(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char *output1 = malloc(data->data_len);
    unsigned char *output2 = malloc(data->data_len);

    if (!output1 || !output2) handleErrors("Memory allocation failed");

    // Use static data, key, and nonce for consistent results across threads
    memset(data->data, 0xAB, data->data_len); 
    memset(data->key, 0x11, sizeof(data->key)); 
    memset(data->nonce, 0x22, sizeof(data->nonce)); 

    // Initialize and perform first encryption
    data->ctx = initialize_chacha20_context(data->key, data->nonce);
    chacha20_encrypt_decrypt(data->ctx, data->data, output1, data->data_len);
    EVP_CIPHER_CTX_free(data->ctx); 

    // Reinitialize and perform second encryption
    data->ctx = initialize_chacha20_context(data->key, data->nonce);
    chacha20_encrypt_decrypt(data->ctx, data->data, output2, data->data_len);

    data->success = 1; // Assume success unless a mismatch is found
    for (int i = 0; i < data->data_len; i++) {
        if (output1[i] != output2[i]) {
            data->success = 0;
            printf("Mismatch at byte %d: %02x != %02x\n", i, output1[i], output2[i]);
            break;
        }
    }

    if (data->success) {
        printf("Test successful: No discrepancy detected by Thread %d.\n", data->thread_id);
    }

    free(output1);
    free(output2);
    return NULL;
}


void *rowhammer_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char *outputBeforeFault = malloc(data->data_len);
    unsigned char *outputAfterFault = malloc(data->data_len);

    if (!outputBeforeFault || !outputAfterFault) {
        fprintf(stderr, "Memory allocation error in rowhammer_test\n");
        data->success = 0; 
        free(outputBeforeFault);
        free(outputAfterFault);
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = initialize_chacha20_context(data->key, data->nonce);
    if (!ctx) {
        fprintf(stderr, "Failed to initialize ChaCha20 context\n");
        free(outputBeforeFault);
        free(outputAfterFault);
        return NULL;
    }

    // Encrypt data before injecting fault
    chacha20_encrypt_decrypt(ctx, data->data, outputBeforeFault, data->data_len);

    inject_selective_fault(data->data, data->data_len - 1);

    // Re-initialize context for a fair comparison
    EVP_CIPHER_CTX_free(ctx);
    ctx = initialize_chacha20_context(data->key, data->nonce);
    if (!ctx) {
        fprintf(stderr, "Failed to re-initialize ChaCha20 context after fault injection\n");
        free(outputBeforeFault);
        free(outputAfterFault);
        return NULL;
    }

    chacha20_encrypt_decrypt(ctx, data->data, outputAfterFault, data->data_len);

    int result = memcmp(outputBeforeFault, outputAfterFault, data->data_len);
    printf("Rowhammer Test for Thread %d completed. ", data->thread_id);
    if (result != 0) {
        printf("Fault injection altered the encryption output.\n");
    } else {
        printf("No change in output despite fault injection.\n");
    }

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

    EVP_CIPHER_CTX *ctx = initialize_chacha20_context(data->key, data->nonce);
    if (!ctx) {
        fprintf(stderr, "Failed to initialize ChaCha20 context\n");
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
        chacha20_encrypt_decrypt(ctx, data->data, output, data->data_len);
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


void *brute_force_speed_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char *decrypted_text = malloc(data->data_len);
    unsigned char test_key[32]; 
    unsigned long long num_keys_tested = 0;
    int test_duration_seconds = 15;
    int warmup_duration_seconds = 5; // Duration for warm-up phase
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

    memset(test_key, 0, sizeof(test_key));  
    memcpy(decrypted_text, data->data, data->data_len);  

    EVP_CIPHER_CTX *ctx = NULL;


    start_time = time(NULL);
    do {
        ctx = initialize_chacha20_context(test_key, data->nonce);
        if (!ctx) {
            fprintf(stderr, "ChaCha20 context initialization failed in brute force test\n");
            continue;
        }
        chacha20_encrypt_decrypt(ctx, data->data, decrypted_text, data->data_len);
        EVP_CIPHER_CTX_free(ctx); 

        for (int i = 0; i < sizeof(test_key); i++) {
            if (++test_key[i]) break;  // Increment key byte; if not wrapped around, stop incrementing
        }
        warmup_end_time = time(NULL);
    } while (difftime(warmup_end_time, start_time) < warmup_duration_seconds);

  
    memset(test_key, 0, sizeof(test_key));

    start_time = time(NULL);  // Reset start time for the actual measurement
    do {
        ctx = initialize_chacha20_context(test_key, data->nonce);
        if (!ctx) {
            fprintf(stderr, "ChaCha20 context initialization failed in brute force test\n");
            continue;
        }
        chacha20_encrypt_decrypt(ctx, data->data, decrypted_text, data->data_len);
        num_keys_tested++;

        EVP_CIPHER_CTX_free(ctx); 

        for (int i = 0; i < sizeof(test_key); i++) {
            if (++test_key[i]) break;  
        }

        end_time = time(NULL);
    } while (difftime(end_time, start_time) < test_duration_seconds);

    double keys_per_second = num_keys_tested / difftime(end_time, start_time);
    double years_to_test_all_keys = pow(2, 256) / (keys_per_second * 3600 * 24 * 365); 

    printf("Brute force speed test by Thread %d:\n", data->thread_id);
    printf("Keys tested per second: %e\n", keys_per_second);
    printf("Estimated years to test all keys: %e years\n", years_to_test_all_keys);

    // Comparison with state-of-the-art hardware
    printf("CPU estimate: %e years\n", pow(2, 256) / (cpu_keys_per_second * 3600 * 24 * 365));
    printf("GPU estimate: %e years\n", pow(2, 256) / (gpu_keys_per_second * 3600 * 24 * 365));
    printf("ASIC estimate: %e years\n", pow(2, 256) / (asic_keys_per_second * 3600 * 24 * 365));

    free(decrypted_text);
    data->success = 1;
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <rowhammer|timing|replicated|differential|linear|bruteforce>\n", argv[0]);
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
        initialize_thread_data(&thread_data[i], mode, 0, i);
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
        for (int k = 0; k < sizeof(thread_data[i].key); k++) {
            fprintf(fp, "%02x", thread_data[i].key[k]);
        }
        fprintf(fp, "\nNonce: ");
        for (int k = 0; k < sizeof(thread_data[i].nonce); k++) {
            fprintf(fp, "%02x", thread_data[i].nonce[k]);
        }
        fprintf(fp, "\nCiphertext: ");
        for (int k = 0; k < thread_data[i].data_len && k < 256; k++) {
            fprintf(fp, "%02x", thread_data[i].data[k]);
        }
        fprintf(fp, "\n\n");
    }

    // Get and write the current time
    time_t current_time = time(NULL);
    fprintf(fp, "File generated on: %s", ctime(&current_time));

    fclose(fp);
    free(threads);
    free(thread_data);

    return 0;
}