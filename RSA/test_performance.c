#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <float.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/sysctl.h>

typedef struct {
    int thread_id;
    EVP_PKEY *pkey;
    int key_length;
    int success;
} ThreadData;

void handleErrors(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

EVP_PKEY *create_rsa_key(int key_length) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) handleErrors("EVP_PKEY_CTX_new_id failed");
    if (EVP_PKEY_keygen_init(ctx) <= 0) handleErrors("EVP_PKEY_keygen_init failed");
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_length) <= 0) handleErrors("EVP_PKEY_CTX_set_rsa_keygen_bits failed");

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) handleErrors("EVP_PKEY_keygen failed");
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

int get_num_cpus() {
    int num_cpus;
    size_t len = sizeof(num_cpus);
    int mib[2] = {CTL_HW, HW_AVAILCPU};

    sysctl(mib, 2, &num_cpus, &len, NULL, 0);
    if (num_cpus < 1) {
        mib[1] = HW_NCPU;
        sysctl(mib, 2, &num_cpus, &len, NULL, 0);
        if (num_cpus < 1) num_cpus = 1;
    }
    return num_cpus;
}

void *factorization_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(data->pkey, NULL);
    BIGNUM *n = NULL;
    if (!EVP_PKEY_get_bn_param(data->pkey, "n", &n)) handleErrors("Failed to get modulus");

    int prime_checks = 0, found = 0;
    for (int i = 2; i < 1000; i++) {
        if (BN_mod_word(n, i) == 0) {
            found = i;
            break;
        }
        prime_checks++;
    }

    FILE *outputFile = fopen("output_2", "a");  // Append mode
    if (outputFile == NULL) {
        fprintf(stderr, "Failed to open output file.\n");
        BN_free(n);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // Write output to file
    if (found) {
        fprintf(outputFile, "Thread ID: %d\n", data->thread_id);
        fprintf(outputFile, "Modulus is divisible by %d.\n\n", found);
        printf("Factorization Test (Thread %d): Modulus is divisible by %d.\n", data->thread_id, found);
    } else {
        fprintf(outputFile, "Thread ID: %d\n", data->thread_id);
        fprintf(outputFile, "%d primes checked, no divisor found.\n\n", prime_checks);
        printf("Factorization Test (Thread %d): %d primes checked, no divisor found.\n", data->thread_id, prime_checks);
    }

    fclose(outputFile);

    BN_free(n);
    EVP_PKEY_CTX_free(ctx);
    return NULL;
}

void *replicated_rsa_execution(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char plaintext[256] = "The quick brown fox jumps over the lazy dog";
    unsigned char encrypted1[512], encrypted2[512];
    unsigned char decrypted1[512], decrypted2[512];
    size_t enc_len1, enc_len2, dec_len1, dec_len2;

    FILE *outputFile = fopen("output_2", "a");  // Append mode
    if (outputFile == NULL) {
        fprintf(stderr, "Failed to open output file.\n");
        return NULL;
    }

    EVP_PKEY_CTX *ctx_enc = EVP_PKEY_CTX_new(data->pkey, NULL);
    EVP_PKEY_CTX *ctx_dec = NULL;

    if (!ctx_enc || EVP_PKEY_encrypt_init(ctx_enc) <= 0) {
        fprintf(stderr, "Encryption initialization failed\n");
        ERR_print_errors_fp(stderr);
        if (ctx_enc) EVP_PKEY_CTX_free(ctx_enc);
        data->success = 0;
        fclose(outputFile);
        return NULL;
    }

    // First encryption
    if (EVP_PKEY_encrypt(ctx_enc, encrypted1, &enc_len1, plaintext, strlen((char *)plaintext)) <= 0) {
        fprintf(stderr, "First encryption failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx_enc);
        data->success = 0;
        fclose(outputFile);
        return NULL;
    }

    // Second encryption
    if (EVP_PKEY_encrypt(ctx_enc, encrypted2, &enc_len2, plaintext, strlen((char *)plaintext)) <= 0) {
        fprintf(stderr, "Second encryption failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx_enc);
        data->success = 0;
        fclose(outputFile);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx_enc); // Free encryption context

    // Initialize decryption context
    ctx_dec = EVP_PKEY_CTX_new(data->pkey, NULL);
    if (!ctx_dec || EVP_PKEY_decrypt_init(ctx_dec) <= 0) {
        fprintf(stderr, "Decryption initialization failed\n");
        ERR_print_errors_fp(stderr);
        if (ctx_dec) EVP_PKEY_CTX_free(ctx_dec);
        data->success = 0;
        fclose(outputFile);
        return NULL;
    }

    // First decryption
    if (EVP_PKEY_decrypt(ctx_dec, decrypted1, &dec_len1, encrypted1, enc_len1) <= 0) {
        fprintf(stderr, "First decryption failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx_dec);
        data->success = 0;
        fclose(outputFile);
        return NULL;
    }

    // Second decryption
    if (EVP_PKEY_decrypt(ctx_dec, decrypted2, &dec_len2, encrypted2, enc_len2) <= 0) {
        fprintf(stderr, "Second decryption failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx_dec);
        data->success = 0;
        fclose(outputFile);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx_dec); // Free decryption context

    // Write output to file
    fprintf(outputFile, "Thread ID: %d\n", data->thread_id);
    fprintf(outputFile, "Ciphertext 1: ");
    for (size_t i = 0; i < enc_len1; i++) {
        fprintf(outputFile, "%02x", encrypted1[i]);
    }
    fprintf(outputFile, "\nCiphertext 2: ");
    for (size_t i = 0; i < enc_len2; i++) {
        fprintf(outputFile, "%02x", encrypted2[i]);
    }
    fprintf(outputFile, "\n\n");

    fclose(outputFile);

    // Compare decrypted texts to the original plaintext
    if (memcmp(decrypted1, decrypted2, dec_len1) != 0 || memcmp(plaintext, decrypted1, dec_len1) != 0) {
        fprintf(stderr, "Discrepancy detected in outputs!\n");
        data->success = 0;
    } else {
        data->success = 1;
        printf("Replicated RSA Test (Thread %d): Successful replication and decryption.\n", data->thread_id);
    }

    return NULL;
}

double estimate_gnfs_complexity(int key_bits) {
    double n = pow(2.0, key_bits);
    double log_n = log2(n);
    double log_log_n = log2(log_n);

    // Continue using the complexity calculation with prevention for overflow
    double complexity_estimate = exp((64.0 / 9.0) * pow(log_n, 1.0/3.0) * pow(log_log_n, 2.0/3.0));

    if (isinf(complexity_estimate)) {
        return DBL_MAX;
    }

    return complexity_estimate;
}

double complexity_to_years(double complexity) {
    if (complexity == DBL_MAX) {
        return DBL_MAX;
    }

    const double flops_per_second = 1e18;  // ExaFLOP/s
    const double seconds_per_year = 60.0 * 60.0 * 24.0 * 365.25;
    double years = complexity / (flops_per_second * seconds_per_year);

    return years;
}

void *brute_force_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    double complexity = estimate_gnfs_complexity(data->key_length);
    double years = complexity_to_years(complexity);

    if (years == DBL_MAX) {
        printf("Thread %d: Key size %d bits - Estimated time to break: inf years (number very large).\n",
               data->thread_id, data->key_length);
    } else {
        printf("Thread %d: Key size %d bits - Estimated time to break: %g years.\n",
               data->thread_id, data->key_length, years);
    }

    return NULL;
}

void print_openssl_errors() {
    ERR_print_errors_fp(stderr);
}

void *rowhammer_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    EVP_PKEY_CTX *ctx_enc, *ctx_dec;
    unsigned char plaintext[256] = "Sample message for RSA encryption";  // Ensure this is less than key size minus padding
    unsigned char encrypted[512], decrypted[512];
    size_t enc_len = sizeof(encrypted), dec_len = sizeof(decrypted);

    // Initialize context for encryption
    ctx_enc = EVP_PKEY_CTX_new(data->pkey, NULL);
    if (!ctx_enc || EVP_PKEY_encrypt_init(ctx_enc) <= 0) {
        fprintf(stderr, "Encryption initialization failed\n");
        print_openssl_errors();
        if (ctx_enc) EVP_PKEY_CTX_free(ctx_enc);
        return NULL;
    }

    // Perform encryption
    if (EVP_PKEY_encrypt(ctx_enc, encrypted, &enc_len, plaintext, strlen((char *)plaintext) + 1) <= 0) {
        fprintf(stderr, "Encryption failed\n");
        print_openssl_errors();
        EVP_PKEY_CTX_free(ctx_enc);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx_enc); // Free encryption context

    // Simulate a fault by modifying the encrypted data
    encrypted[0] ^= 0x01; // Flip the least significant bit of the first byte

    // Initialize context for decryption
    ctx_dec = EVP_PKEY_CTX_new(data->pkey, NULL);
    if (!ctx_dec || EVP_PKEY_decrypt_init(ctx_dec) <= 0) {
        fprintf(stderr, "Decryption initialization failed\n");
        print_openssl_errors();
        if (ctx_dec) EVP_PKEY_CTX_free(ctx_dec);
        return NULL;
    }

    // Attempt to decrypt the modified ciphertext
    if (EVP_PKEY_decrypt(ctx_dec, decrypted, &dec_len, encrypted, enc_len) <= 0) {
        fprintf(stderr, "Decryption failed with modified ciphertext\n");
        print_openssl_errors();
        EVP_PKEY_CTX_free(ctx_dec);
        return NULL;
    }

    printf("Rowhammer Test (Thread %d): Decryption successful even with modified ciphertext.\n", data->thread_id);
    EVP_PKEY_CTX_free(ctx_dec); // Free decryption context

    return NULL;
}

void *differential_cryptanalysis_rsa(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char plaintext[200] = "The quick brown fox jumps over";  // Adjusted size to fit padding requirements
    unsigned char modified_plaintext[200];
    memcpy(modified_plaintext, plaintext, sizeof(plaintext));
    modified_plaintext[0] ^= 0x01;  // Flip the first bit

    unsigned char encrypted[512], modified_encrypted[512];
    size_t enc_len, mod_enc_len;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(data->pkey, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) {
        fprintf(stderr, "Encryption context initialization failed\n");
        if (ctx) EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // Encrypt original plaintext
    if (EVP_PKEY_encrypt(ctx, encrypted, &enc_len, plaintext, sizeof(plaintext)) <= 0) {
        fprintf(stderr, "Encryption failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // Encrypt modified plaintext
    if (EVP_PKEY_encrypt(ctx, modified_encrypted, &mod_enc_len, modified_plaintext, sizeof(modified_plaintext)) <= 0) {
        fprintf(stderr, "Encryption of modified plaintext failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);

    // Compare outputs and summarize the result
    int differences = 0;
    size_t min_len = (enc_len < mod_enc_len) ? enc_len : mod_enc_len;
    for (size_t i = 0; i < min_len; i++) {
        if (encrypted[i] != modified_encrypted[i]) differences++;
    }

    printf("Differential Cryptanalysis Test for RSA (Thread %d): Differences: %d\n", data->thread_id, differences);
    return NULL;
}

void *linear_cryptanalysis_rsa(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char plaintext[200] = "Sample plaintext data for RSA";  // Adjusted size for RSA padding
    unsigned char encrypted[512];
    size_t enc_len;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(data->pkey, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) {
        fprintf(stderr, "Encryption context initialization failed\n");
        if (ctx) EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // Encrypt the data
    if (EVP_PKEY_encrypt(ctx, encrypted, &enc_len, plaintext, sizeof(plaintext)) <= 0) {
        fprintf(stderr, "Encryption failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);

    printf("Linear Cryptanalysis Test for RSA (Thread %d): Encrypted Size: %zu\n", data->thread_id, enc_len);
    return NULL;
}

void *timing_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char plaintext[214] = "The quick brown fox jumps over the lazy dog";
    unsigned char ciphertext[256], decrypted[256];
    size_t encrypted_length, decrypted_length;
    struct timeval start, end;

    EVP_PKEY_CTX *ctx_enc = EVP_PKEY_CTX_new(data->pkey, NULL);
    if (EVP_PKEY_encrypt_init(ctx_enc) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx_enc, RSA_PKCS1_OAEP_PADDING) <= 0) {
        handleErrors("Encryption setup failed");
    }

    gettimeofday(&start, NULL);
    if (EVP_PKEY_encrypt(ctx_enc, ciphertext, &encrypted_length, plaintext, strlen((char *)plaintext) + 1) <= 0) {
        ERR_print_errors_fp(stderr);
        handleErrors("Encryption failed");
    }
    gettimeofday(&end, NULL);

    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
    printf("Timing Test (Thread %d): Encryption took %.6f seconds.\n", data->thread_id, elapsed);

    EVP_PKEY_CTX *ctx_dec = EVP_PKEY_CTX_new(data->pkey, NULL);
    if (EVP_PKEY_decrypt_init(ctx_dec) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx_dec, RSA_PKCS1_OAEP_PADDING) <= 0) {
        handleErrors("Decryption setup failed");
    }

    gettimeofday(&start, NULL);
    if (EVP_PKEY_decrypt(ctx_dec, decrypted, &decrypted_length, ciphertext, encrypted_length) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Decryption failed\n");
    } else {
        gettimeofday(&end, NULL);
        elapsed = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
        printf("Timing Test (Thread %d): Decryption took %.6f seconds.\n", data->thread_id, elapsed);
    }

    EVP_PKEY_CTX_free(ctx_enc);
    EVP_PKEY_CTX_free(ctx_dec);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <test_type> <key_size>\n", argv[0]);
        return 1;
    }

    int key_size = atoi(argv[2]);
    if (key_size != 2048 && key_size != 4096) {
        fprintf(stderr, "Invalid key size. Please choose 2048 or 4096.\n");
        return 1;
    }

    int num_cpus = get_num_cpus();
    pthread_t threads[num_cpus];
    ThreadData thread_data[num_cpus];

    void *(*selected_test)(void *) = NULL;

    // Select the test based on command line arguments
    if (strcmp(argv[1], "factorization") == 0) {
        selected_test = factorization_test;
    } else if (strcmp(argv[1], "timing") == 0) {
        selected_test = timing_test;
    } else if (strcmp(argv[1], "brute_force") == 0) {
        selected_test = brute_force_test;
    } else if (strcmp(argv[1], "rowhammer") == 0) {
        selected_test = rowhammer_test;
    } else if (strcmp(argv[1], "replication") == 0) {
        selected_test = replicated_rsa_execution;
    } else if (strcmp(argv[1], "differential") == 0) {
        selected_test = differential_cryptanalysis_rsa;
    } else if (strcmp(argv[1], "linear") == 0) {
        selected_test = linear_cryptanalysis_rsa;
    } else {
        fprintf(stderr, "Invalid test type. Available tests: factorization, timing, brute_force, rowhammer, replicated_rsa, differential_rsa, linear_rsa\n");
        return 1;
    }

    // Initialize RSA keys and thread data
    for (int i = 0; i < num_cpus; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].pkey = create_rsa_key(key_size);  // All threads use the same key size specified
        pthread_create(&threads[i], NULL, selected_test, &thread_data[i]);
    }

    // Wait for all threads to finish
    for (int i = 0; i < num_cpus; i++) {
        pthread_join(threads[i], NULL);
        EVP_PKEY_free(thread_data[i].pkey);  // Clean up keys
    }

    return 0;
}