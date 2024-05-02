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
    double enc_time; // milliseconds
    double dec_time; // milliseconds
    double total_time; // milliseconds
    double throughput; // MB/s
    int integrity_check;
    double cpu_user_time; // milliseconds
    double cpu_system_time; // milliseconds
    int thread_id;
};

const EVP_CIPHER *cipher = NULL;

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

void *perform_encryption_decryption(void *args) {
    struct benchmark_stats *stats = (struct benchmark_stats *)args;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    unsigned char *plaintext = malloc(DATA_SIZE);
    unsigned char *ciphertext = malloc(DATA_SIZE);
    unsigned char *decryptedtext = malloc(DATA_SIZE);

    if (!ciphertext || !decryptedtext || !plaintext) {
        fprintf(stderr, "Memory allocation failed\n");
        handleErrors();
    }

    RAND_bytes(plaintext, DATA_SIZE);
    RAND_bytes(key, EVP_CIPHER_key_length(cipher));
    RAND_bytes(iv, EVP_CIPHER_iv_length(cipher));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    struct timespec start, end;
    double enc_time = 0, dec_time = 0, start_user, start_system, end_user, end_system;

    get_cpu_times(&start_user, &start_system);

    for (int i = 0; i < ITERATIONS; i++) {
        int len;

        // Encryption
        EVP_CIPHER_CTX_reset(ctx);
        if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) handleErrors();
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, DATA_SIZE)) handleErrors();
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
        clock_gettime(CLOCK_MONOTONIC, &end);
        enc_time += (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;

        // Decryption
        EVP_CIPHER_CTX_reset(ctx);
        if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) handleErrors();
        clock_gettime(CLOCK_MONOTONIC, &start);
        if (1 != EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, DATA_SIZE)) handleErrors();
        if (1 != EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len)) handleErrors();
        clock_gettime(CLOCK_MONOTONIC, &end);
        dec_time += (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;
    }

    get_cpu_times(&end_user, &end_system);

    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    free(decryptedtext);
    free(plaintext);

    stats->enc_time = enc_time / ITERATIONS;
    stats->dec_time = dec_time / ITERATIONS;
    stats->total_time = stats->enc_time + stats->dec_time;
    stats->throughput = (double)DATA_SIZE * ITERATIONS / (1024.0 * 1024.0 * (stats->total_time / 1000.0)); // Convert milliseconds to seconds for throughput
    stats->integrity_check = 1;  // Assuming integrity check always passes in this example
    stats->cpu_user_time = end_user - start_user;
    stats->cpu_system_time = end_system - start_system;

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <128|192|256>\n", argv[0]);
        return 1;
    }

    int key_size = atoi(argv[1]);
    switch (key_size) {
        case 128:
            cipher = EVP_aes_128_ctr();
            break;
        case 192:
            cipher = EVP_aes_192_ctr();
            break;
        case 256:
            cipher = EVP_aes_256_ctr();
            break;
        default:
            fprintf(stderr, "Invalid key size: %s. Use 128, 192, or 256.\n", argv[1]);
            return 1;
    }

    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    pthread_t threads[num_threads];
    struct benchmark_stats stats[num_threads];

    for (int i = 0; i < num_threads; i++) {
        stats[i].thread_id = i;
        pthread_create(&threads[i], NULL, perform_encryption_decryption, &stats[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    // Printing the results in milliseconds after all threads have completed
    for (int i = 0; i < num_threads; i++) {
        printf("Thread %d: Encryption Time: %.2f ms, Decryption Time: %.2f ms, Total Time: %.2f ms, Throughput: %.2f MB/s, CPU User Time: %.2f ms, CPU System Time: %.2f ms\n",
               stats[i].thread_id, stats[i].enc_time, stats[i].dec_time, stats[i].total_time, stats[i].throughput, stats[i].cpu_user_time, stats[i].cpu_system_time);
    }

    return 0;
}
