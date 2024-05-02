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
#include <oqs/oqs.h>
#include <stddef.h>


#define DATA_SIZE (1024 * 1024 8 50) // 1 MB for more realistic testing
#define ITERATIONS 10

typedef struct {
    int thread_id;
    unsigned char *data;
    unsigned char public_key[OQS_KEM_kyber_512_length_public_key];
    unsigned char secret_key[OQS_KEM_kyber_512_length_secret_key];
    unsigned char ciphertext[OQS_KEM_kyber_512_length_ciphertext];
    unsigned char shared_secret_e[OQS_KEM_kyber_512_length_shared_secret];
    unsigned char shared_secret_d[OQS_KEM_kyber_512_length_shared_secret];
    int data_len;
    int success;
    char *attack_type;
    int introduce_fault;
    int security_bits; 
    struct timespec start_time, end_time;
    struct rusage usage_start, usage_end;
    OQS_KEM *kem;
    char result_string[512];
    unsigned long long keys_tested;
    double average_keys_per_second;
    double keys_per_second;
    double years_to_exhaust;
} ThreadData;

void handleErrors(const char* error) {
    fprintf(stderr, "Error: %s\n", error);
    exit(1);
}

void *perform_kyber_operations(void *args) {
    ThreadData *data = (ThreadData *)args;
    data->kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (data->kem == NULL) {
        fprintf(stderr, "New Kyber instance failed.\n");
        data->success = 0;
        return NULL;
    }

    // Key Generation
    OQS_KEM_keypair(data->kem, data->public_key, data->secret_key);

    // Encapsulation
    OQS_KEM_encaps(data->kem, data->ciphertext, data->shared_secret_e, data->public_key);

    // Decapsulation
    OQS_KEM_decaps(data->kem, data->shared_secret_d, data->ciphertext, data->secret_key);

    // Simulate a fault attack if enabled
    if (data->introduce_fault) {
        data->ciphertext[0] ^= 1; // Flip the first bit of the ciphertext
    }

    // Repeat Decapsulation to check the effect of the fault
    OQS_KEM_decaps(data->kem, data->shared_secret_d, data->ciphertext, data->secret_key);

    // Clean up
    OQS_KEM_free(data->kem);
    data->success = 1;
    return NULL;
}

void *timing_analysis(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    struct timespec start, end;
    double times[ITERATIONS], sum = 0.0, mean, stddev = 0.0;

    data->kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (data->kem == NULL) {
        fprintf(stderr, "New Kyber instance failed.\n");
        data->success = 0;
        return NULL;
    }

    for (int i = 0; i < ITERATIONS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        OQS_KEM_keypair(data->kem, data->public_key, data->secret_key);
        OQS_KEM_encaps(data->kem, data->ciphertext, data->shared_secret_e, data->public_key);
        OQS_KEM_decaps(data->kem, data->shared_secret_d, data->ciphertext, data->secret_key);
        clock_gettime(CLOCK_MONOTONIC, &end);

        times[i] = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
        sum += times[i];
    }

    mean = sum / ITERATIONS;
    for (int i = 0; i < ITERATIONS; i++) {
        stddev += (times[i] - mean) * (times[i] - mean);
    }
    stddev = sqrt(stddev / ITERATIONS);

    printf("Timing Analysis: Mean = %.6f s, StdDev = %.6f s\n", mean, stddev);

    OQS_KEM_free(data->kem);
    data->success = 1;
    return NULL;
}

void inject_selective_fault(unsigned char *data, size_t data_length, int num_faults) {
    srand((unsigned int)time(NULL)); // Seed the random number generator with current time

    for (int i = 0; i < num_faults; i++) {
        size_t position = rand() % (data_length * 8); // Calculate random bit position
        size_t byte_index = position / 8;
        unsigned char bit_mask = 1 << (position % 8);

        data[byte_index] ^= bit_mask; // Flip the bit
    }
}

void *rowhammer_kyber_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char shared_secret1[OQS_KEM_kyber_512_length_shared_secret];
    unsigned char shared_secret2[OQS_KEM_kyber_512_length_shared_secret];
    unsigned char ciphertext[OQS_KEM_kyber_512_length_ciphertext];
    unsigned char public_key[OQS_KEM_kyber_512_length_public_key];
    unsigned char secret_key[OQS_KEM_kyber_512_length_secret_key];

    // Initialize KEM
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem) {
        fprintf(stderr, "Failed to initialize Kyber KEM instance\n");
        data->success = 0;
        return NULL;
    }

    // Generate a keypair
    OQS_KEM_keypair(kem, public_key, secret_key);

    // Encapsulate to generate the original shared secret and ciphertext
    OQS_KEM_encaps(kem, ciphertext, shared_secret1, public_key);

    // Simulate a rowhammer attack by modifying the ciphertext with random bit flips
    inject_selective_fault(ciphertext, OQS_KEM_kyber_512_length_ciphertext, 5); // Example: flip 5 random bits

    // Decapsulate the modified ciphertext
    OQS_KEM_decaps(kem, shared_secret2, ciphertext, secret_key);

    // Compare the original and the post-fault shared secrets
    int result = memcmp(shared_secret1, shared_secret2, OQS_KEM_kyber_512_length_shared_secret);
    printf("Rowhammer Test for Thread %d completed. ", data->thread_id);
    if (result != 0) {
        printf("Fault injection altered the decryption output.\n");
    } else {
        printf("No change in output despite fault injection.\n");
    }

    // Clean up
    OQS_KEM_free(kem);

    data->success = 1; // Indicate success, irrespective of whether fault altered output
    return NULL;
}

void perform_warmup(OQS_KEM *kem, unsigned char *ciphertext, int warmup_duration);
void *brute_force_kyber_test(void *arg);

void *brute_force_kyber_test(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char shared_secret[OQS_KEM_kyber_512_length_shared_secret];
    unsigned char ciphertext[OQS_KEM_kyber_512_length_ciphertext];
    unsigned char public_key[OQS_KEM_kyber_512_length_public_key];
    unsigned char secret_key[OQS_KEM_kyber_512_length_secret_key];

    // Initialize KEM
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem) {
        fprintf(stderr, "Failed to initialize Kyber KEM instance\n");
        data->success = 0;
        return NULL;
    }

    OQS_KEM_keypair(kem, public_key, secret_key);
    OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);

    unsigned long long num_keys_tested = 0;
    struct timeval start_time, current_time;
    gettimeofday(&start_time, NULL);
    long long elapsed_microseconds;

    do {
        unsigned char test_secret_key[OQS_KEM_kyber_512_length_secret_key];
        OQS_randombytes(test_secret_key, sizeof(test_secret_key)); // Fill test_secret_key with random bytes

        unsigned char test_shared_secret[OQS_KEM_kyber_512_length_shared_secret];
        OQS_KEM_decaps(kem, test_shared_secret, ciphertext, test_secret_key);

        num_keys_tested++;

        gettimeofday(&current_time, NULL);
        elapsed_microseconds = (current_time.tv_sec - start_time.tv_sec) * 1000000LL + (current_time.tv_usec - start_time.tv_usec);
    } while (elapsed_microseconds < 5000000); // Loop runs for exactly 5 seconds

    data->keys_tested = num_keys_tested;
    data->average_keys_per_second = (double)num_keys_tested / 5.0; // Average keys per second over 5 seconds
    double keyspace_size = pow(2, data->security_bits); // Calculate the total keyspace size
    data->years_to_exhaust = keyspace_size / (data->average_keys_per_second * 3600 * 24 * 365);

    printf("Thread %d: Total keys tested: %llu, Average Keys/sec: %.2f, Years to exhaust a %d-bit keyspace: %.2e years\n",
           data->thread_id, num_keys_tested, data->average_keys_per_second, data->security_bits, data->years_to_exhaust);

    OQS_KEM_free(kem);
    data->success = 1;
    return NULL;
}

void perform_warmup(OQS_KEM *kem, unsigned char *ciphertext, int warmup_duration) {
    struct timeval start_time, current_time;
    gettimeofday(&start_time, NULL);
    long long elapsed_seconds;
    do {
        unsigned char test_secret_key[OQS_KEM_kyber_512_length_secret_key];
        OQS_randombytes(test_secret_key, sizeof(test_secret_key));
        unsigned char test_shared_secret[OQS_KEM_kyber_512_length_shared_secret];
        OQS_KEM_decaps(kem, test_shared_secret, ciphertext, test_secret_key);

        gettimeofday(&current_time, NULL);
        elapsed_seconds = current_time.tv_sec - start_time.tv_sec;
    } while (elapsed_seconds < warmup_duration);
}

void *replicated_execution(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char shared_secret1[OQS_KEM_kyber_512_length_shared_secret];
    unsigned char shared_secret2[OQS_KEM_kyber_512_length_shared_secret];

    data->kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (data->kem == NULL) {
        fprintf(stderr, "New Kyber instance failed.\n");
        data->success = 0;
        return NULL;
    }

    OQS_KEM_keypair(data->kem, data->public_key, data->secret_key);
    OQS_KEM_encaps(data->kem, data->ciphertext, shared_secret1, data->public_key);
    OQS_KEM_encaps(data->kem, data->ciphertext, shared_secret2, data->public_key);

    if (memcmp(shared_secret1, shared_secret2, OQS_KEM_kyber_512_length_shared_secret) != 0) {
        fprintf(stderr, "Replicated execution produced different results.\n");
        data->success = 0;
    } else {
        data->success = 1;
    }

    OQS_KEM_free(data->kem);
    return NULL;
}

void *differential_cryptanalysis_kyber(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char public_key[OQS_KEM_kyber_512_length_public_key];
    unsigned char secret_key[OQS_KEM_kyber_512_length_secret_key];
    unsigned char ciphertext[OQS_KEM_kyber_512_length_ciphertext];
    unsigned char shared_secret1[OQS_KEM_kyber_512_length_shared_secret];
    unsigned char shared_secret2[OQS_KEM_kyber_512_length_shared_secret];

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem) {
        fprintf(stderr, "Failed to initialize Kyber KEM instance\n");
        data->success = 0;
        return NULL;
    }

    OQS_KEM_keypair(kem, public_key, secret_key);
    OQS_KEM_encaps(kem, ciphertext, shared_secret1, public_key);

    // Introduce a small change: flip a bit in the public key
    public_key[0] ^= 0x01;
    OQS_KEM_encaps(kem, ciphertext, shared_secret2, public_key);

    int differences = 0;
    for (int i = 0; i < OQS_KEM_kyber_512_length_shared_secret; i++) {
        if (shared_secret1[i] != shared_secret2[i]) differences++;
    }

    printf("Differential Cryptanalysis for Kyber - Thread %d: Differences in shared secret: %d\n", data->thread_id, differences);

    OQS_KEM_free(kem);
    data->success = 1;
    return NULL;
}

void *linear_cryptanalysis_kyber(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned char public_key[OQS_KEM_kyber_512_length_public_key];
    unsigned char secret_key[OQS_KEM_kyber_512_length_secret_key];
    unsigned char ciphertext[OQS_KEM_kyber_512_length_ciphertext];
    unsigned char shared_secret[OQS_KEM_kyber_512_length_shared_secret];

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem) {
        fprintf(stderr, "Failed to initialize Kyber KEM instance\n");
        data->success = 0;
        return NULL;
    }

    OQS_KEM_keypair(kem, public_key, secret_key);
    OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);

    // Analyze output for non-randomness (e.g., check if even bits have a pattern)
    int even_bit_count = 0;
    for (int i = 0; i < OQS_KEM_kyber_512_length_shared_secret; i++) {
        for (int j = 0; j < 8; j += 2) {
            even_bit_count += (shared_secret[i] >> j) & 1;
        }
    }

    printf("Linear Cryptanalysis for Kyber - Thread %d: Even bit count: %d\n", data->thread_id, even_bit_count);

    OQS_KEM_free(kem);
    data->success = 1;
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <security_bits> <test_type>\n", argv[0]);
        return 1;
    }

    int security_bits = atoi(argv[1]); // Get the security level
    char *test_type = argv[2];
    int num_threads = sysconf(_SC_NPROCESSORS_ONLN); // Get the number of online processors
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    ThreadData *thread_data = calloc(num_threads, sizeof(ThreadData));

    if (!threads || !thread_data) {
        fprintf(stderr, "Failed to allocate memory for threads or thread data\n");
        return 1;
    }

    void *(*selected_test)(void *) = NULL;

    // Determine which test to run based on the command-line argument
    if (strcmp(test_type, "replicated") == 0) {
        selected_test = replicated_execution;
    } else if (strcmp(test_type, "timing") == 0) {
        selected_test = timing_analysis;
    } else if (strcmp(test_type, "rowhammer") == 0) {
        selected_test = rowhammer_kyber_test;
    } else if (strcmp(test_type, "bruteforce") == 0) {
        selected_test = brute_force_kyber_test;
    } else if (strcmp(test_type, "differential") == 0) {
        selected_test = differential_cryptanalysis_kyber;
    } else if (strcmp(test_type, "linear") == 0) {
        selected_test = linear_cryptanalysis_kyber;
    } else {
        fprintf(stderr, "Invalid test type. Valid options are 'replicated', 'timing', 'rowhammer', 'bruteforce', 'differential', or 'linear'.\n");
        free(threads);
        free(thread_data);
        return 1;
    }

    // Set security_bits and create a thread for each processor
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].security_bits = security_bits;  // Set security level for all threads
        pthread_create(&threads[i], NULL, selected_test, &thread_data[i]);
    }

    // Wait for all threads to finish
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    // Clean up
    free(threads);
    free(thread_data);
    return 0;
}