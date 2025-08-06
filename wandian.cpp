/*MIT License

Copyright (c) 2025 8891689
                    https://github.com/8891689
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
g++ -O3 -march=native wandian.cpp -static -o wandian -lpthread
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <chrono>
#include <new>
#include <stdbool.h>
#include <vector>
#include <numeric>
#include <algorithm>
#include <string> 

// ==================== Constants and type definitions ====================
#define MAX_PASSWORD_LENGTH 256
// Use the 128-bit integer type for all password counting
typedef unsigned __int128 u128;

typedef struct {
    const char *identifier;
    const char *characters;
} Charset;

const Charset CHARSETS[] = {
    {"d", "0123456789"},
    {"u", "abcdefghijklmnopqrstuvwxyz"},
    {"i", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
    {"h", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"},
    {"j", "0123456789abcdef"},
    {"k", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"},
    {"s", " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"},
    {"all", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:'\",.<>?/~"}
};
#define NUM_CHARSETS (sizeof(CHARSETS) / sizeof(CHARSETS[0]))

// ==================== 128-bit Helper Functions ====================
// Custom power function returning u128 to prevent overflow
u128 int_pow128(int base, int exp) {
    u128 result = 1;
    for(int i = 0; i < exp; i++) {
        // The compiler knows how to check overflow for u128
        u128 temp_res;
        if (__builtin_mul_overflow(result, base, &temp_res)) return 0; // Return 0 on overflow
        result = temp_res;
    }
    return result;
}

// Custom print function for u128, as printf doesn't support it
void print_u128(u128 n) {
    if (n == 0) {
        printf("0");
        return;
    }
    std::string s = "";
    while (n > 0) {
        s += (n % 10) + '0';
        n /= 10;
    }
    std::reverse(s.begin(), s.end());
    printf("%s", s.c_str());
}


// ==================== High-speed PRNG & range mapping ====================
struct Xoshiro256StarStar {
    uint64_t s[4];
    static inline uint64_t rotl(const uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
    uint64_t next(void) {
        const uint64_t result = rotl(s[1] * 5, 7) * 9;
        const uint64_t t = s[1] << 17;
        s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3];
        s[2] ^= t; s[3] = rotl(s[3], 45);
        return result;
    }
    void seed(uint64_t seed) {
        for (int i = 0; i < 4; ++i) {
            uint64_t x = seed += 0x9e3779b97f4a7c15;
            x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9;
            x = (x ^ (x >> 27)) * 0x94d049bb133111eb;
            s[i] = x ^ (x >> 31);
        }
    }
};
static inline uint32_t fast_map_to_range(uint64_t rand64, uint32_t range) {
    return (uint32_t)(((unsigned __int128)rand64 * range) >> 64);
}

// ==================== Thread data structure  ====================
typedef struct {
    u128 startIndex;
    u128 endIndex;
    int minLength;
    int maxLength;
    bool random;
    FILE *file;
    pthread_mutex_t *mutex;
    const char *charset;
    int charsetLength;
    bool infinite; 
    const std::vector<u128>* start_indices_per_length;
} ThreadData;


// ==================== Thread-generated password function  ====================
void* generatePasswords(void* arg) {
    ThreadData *data = (ThreadData *)arg;
    const size_t WRITE_BUFFER_SIZE = 1024 * 1024;
    char* write_buffer = new (std::nothrow) char[WRITE_BUFFER_SIZE];
    if (!write_buffer) {
        fprintf(stderr, "Warning: Thread failed to allocate write buffer.\n");
        return NULL;
    }
    size_t buffer_offset = 0;
    auto flush_buffer = [&]() {
        if (buffer_offset > 0) {
            pthread_mutex_lock(data->mutex);
            fwrite(write_buffer, sizeof(char), buffer_offset, data->file);
            pthread_mutex_unlock(data->mutex);
            buffer_offset = 0;
        }
    };

    if (data->random) {
        Xoshiro256StarStar gen;
        uint64_t thread_seed = std::chrono::high_resolution_clock::now().time_since_epoch().count() ^ (uint64_t)pthread_self() ^ (uint64_t)(uintptr_t)data;
        gen.seed(thread_seed);
        char password[MAX_PASSWORD_LENGTH + 1];
        const uint32_t charsetLength = data->charsetLength;
        const int minLen = data->minLength;
        const uint32_t len_range = data->maxLength - minLen + 1;
        long long total_count = data->infinite ? -1 : (long long)(data->endIndex - data->startIndex);
        for (long long count = 0; data->infinite || count < total_count; ++count) {
            int passwordLength = minLen;
            if (len_range > 1) passwordLength += fast_map_to_range(gen.next(), len_range);
            for(int i = 0; i < passwordLength; ++i) {
                password[i] = data->charset[fast_map_to_range(gen.next(), charsetLength)];
            }
            int required_len = passwordLength + 1;
            if (WRITE_BUFFER_SIZE - buffer_offset < required_len + 1) flush_buffer();
            memcpy(write_buffer + buffer_offset, password, passwordLength);
            buffer_offset += passwordLength;
            write_buffer[buffer_offset++] = '\n';
        }
    } else { 
        const std::vector<u128>& start_indices = *data->start_indices_per_length;
        const char* charset = data->charset;
        const int charsetLength = data->charsetLength;
        auto it = std::upper_bound(start_indices.begin(), start_indices.end(), data->startIndex);
        int current_len_offset = std::distance(start_indices.begin(), it) - 1;
        int current_len = data->minLength + current_len_offset;
        
        u128 local_idx = data->startIndex - start_indices[current_len_offset];
        
        int indices[MAX_PASSWORD_LENGTH] = {0}; 
        u128 temp_idx = local_idx;
        for (int pos = current_len - 1; pos >= 0; --pos) {
            indices[pos] = (int)(temp_idx % charsetLength);
            temp_idx /= charsetLength;
        }

        u128 passwords_to_generate = data->endIndex - data->startIndex;
        char password_buffer[MAX_PASSWORD_LENGTH + 1];

        for (u128 i = 0; i < passwords_to_generate; ++i) {
            for (int j = 0; j < current_len; ++j) {
                password_buffer[j] = charset[indices[j]];
            }
            int required_len = current_len + 1;
            if (WRITE_BUFFER_SIZE - buffer_offset < required_len + 1) flush_buffer();
            memcpy(write_buffer + buffer_offset, password_buffer, current_len);
            buffer_offset += current_len;
            write_buffer[buffer_offset++] = '\n';
            
            for (int pos = current_len - 1; pos >= 0; --pos) {
                indices[pos]++;
                if (indices[pos] < charsetLength) break;
                indices[pos] = 0;
                if (pos == 0) {
                    current_len++;
                    current_len_offset++;
                }
            }
        }
    }

    flush_buffer();
    delete[] write_buffer;
    return NULL;
}

// ==================== Main dictionary generation logic  ====================
void generateDictionary(u128 numPasswords, int minLength, int maxLength, int threads, bool random, FILE *file, const char *charset, int charsetLength, bool infinite) {
    pthread_t *threadIds = new (std::nothrow) pthread_t[threads];
    if(!threadIds) { perror("Memory allocation failed (threadIds)"); return; }

    ThreadData *threadData = new (std::nothrow) ThreadData[threads];
    if(!threadData) { perror("Memory allocation failed (threadData)"); delete[] threadIds; return; }

    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    
    std::vector<u128> start_indices_per_length;

    if (random) {
        u128 passwordsPerThread = numPasswords / threads;
        u128 remainder = numPasswords % threads;
        u128 current_start = 0;

        for(int i = 0; i < threads; ++i) {
            threadData[i].startIndex = current_start;
            u128 chunk_size = passwordsPerThread + (i < remainder ? 1 : 0);
            threadData[i].endIndex = current_start + chunk_size;
            current_start = threadData[i].endIndex;
            threadData[i].random = true; threadData[i].infinite = infinite;
            threadData[i].minLength = minLength; threadData[i].maxLength = maxLength;
            threadData[i].file = file; threadData[i].mutex = &mutex;
            threadData[i].charset = charset; threadData[i].charsetLength = charsetLength;
            threadData[i].start_indices_per_length = nullptr;
            if(pthread_create(&threadIds[i], NULL, generatePasswords, &threadData[i]) != 0) {
                 fprintf(stderr, "Error: Failed to create thread %d\n", i);
                 for(int j=0; j<i; ++j) { pthread_cancel(threadIds[j]); pthread_join(threadIds[j], NULL); }
                 goto cleanup;
            }
        }
        for(int i = 0; i < threads; ++i) pthread_join(threadIds[i], NULL);
    } else {
        u128 totalPasswords = 0;
        start_indices_per_length.reserve(maxLength - minLength + 1);

        for (int len = minLength; len <= maxLength; ++len) {
            u128 count_for_len = int_pow128(charsetLength, len);
            if (count_for_len == 0 && (charsetLength > 1 || len > 0)) {
                fprintf(stderr, "Error: Password combination count for length %d overflowed.\n", len);
                goto cleanup;
            }
            start_indices_per_length.push_back(totalPasswords);
            u128 temp_total;
            if (__builtin_add_overflow(totalPasswords, count_for_len, &temp_total)) {
                fprintf(stderr, "Error: Total password combination count overflowed.\n");
                goto cleanup;
            }
            totalPasswords = temp_total;
        }

        printf("Total combinations to generate: ");
        print_u128(totalPasswords);
        printf(".\n");

        u128 passwordsPerThread = totalPasswords / threads;
        u128 remainder = totalPasswords % threads;
        u128 current_start_index = 0;

        for (int i = 0; i < threads; i++) {
            threadData[i].startIndex = current_start_index;
            u128 chunk_size = passwordsPerThread + (i < remainder ? 1 : 0);
            threadData[i].endIndex = current_start_index + chunk_size;
            current_start_index = threadData[i].endIndex;
            threadData[i].random = false; threadData[i].infinite = false; 
            threadData[i].minLength = minLength; threadData[i].maxLength = maxLength;
            threadData[i].file = file; threadData[i].mutex = &mutex;
            threadData[i].charset = charset; threadData[i].charsetLength = charsetLength;
            threadData[i].start_indices_per_length = &start_indices_per_length;
            if (pthread_create(&threadIds[i], NULL, generatePasswords, &threadData[i]) != 0) {
                fprintf(stderr, "Error: Failed to create thread %d\n", i);
                for(int j=0; j < i; ++j) { pthread_cancel(threadIds[j]); pthread_join(threadIds[j], NULL); }
                goto cleanup;
            }
        }
        for (int i = 0; i < threads; i++) pthread_join(threadIds[i], NULL);
    }

cleanup:
    pthread_mutex_destroy(&mutex);
    delete[] threadIds;
    delete[] threadData;
}

// ==================== Main function and command line parsing ====================
void parseLengthRange(char *range, int *minLength, int *maxLength) {
    char *dashPos = strchr(range, '-');
    if(dashPos) { *dashPos = '\0'; *minLength = atoi(range); *maxLength = atoi(dashPos + 1); } 
    else { *minLength = *maxLength = atoi(range); }
}

void printHelp() {
    printf("Usage: wandian [-n num] [-t threads] [-l length] [-c charset] [-R] [-o outputFile]\n");
    printf("  -n num           : Number of passwords to generate (only for -R random mode).\n");
    printf("                     In sequential mode, this option is ignored.\n");
    printf("  -t threads       : Number of threads to use (default: 1).\n");
    printf("  -l length        : Password length range (e.g., 8-10 or 8 for fixed).\n");
    printf("  -c charset       : Character sets (d,u,i,h,j,k,s,all), comma-separated.\n");
    printf("  -R               : Random password generation. If -n is not specified, it runs infinitely.\n");
    printf("  -o outputFile    : Output file name. Prints to console if not specified.\n");
    printf("  -h, --help       : Show this help message.\n");
    printf("     author        : https://github.com/8891689 \n");
}

int main(int argc, char *argv[]) {
    long long numPasswords_ll = 100000000;
    int minLength = 8, maxLength = 8;
    int threads = 1;
    bool random = false, n_specified = false, infinite = false;
    char *outputFile = NULL;
    char selectedCharsets[1024] = {0};

    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "-R") == 0) random = true;
        else if(strcmp(argv[i], "-t") == 0 && i + 1 < argc) threads = atoi(argv[++i]);
        else if(strcmp(argv[i], "-n") == 0 && i + 1 < argc) { numPasswords_ll = atoll(argv[++i]); n_specified = true; }
        else if(strcmp(argv[i], "-o") == 0 && i + 1 < argc) outputFile = argv[++i];
        else if(strcmp(argv[i], "-l") == 0 && i + 1 < argc) parseLengthRange(argv[++i], &minLength, &maxLength);
        else if(strcmp(argv[i], "-c") == 0 && i + 1 < argc) strncpy(selectedCharsets, argv[++i], sizeof(selectedCharsets) - 1);
        else if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) { printHelp(); return 0; }
        else { fprintf(stderr, "Error: Unknown or missing argument for '%s'\n", argv[i]); printHelp(); return 1; }
    }

    if(threads <= 0) { fprintf(stderr, "Error: Number of threads must be greater than 0.\n"); return 1; }
    if(strlen(selectedCharsets) == 0) strcpy(selectedCharsets, "all");
    
    char combinedCharset[4096] = {0};
    char selectedCharsets_copy[1024];
    strncpy(selectedCharsets_copy, selectedCharsets, sizeof(selectedCharsets_copy) - 1);
    selectedCharsets_copy[sizeof(selectedCharsets_copy)-1] = '\0';
    char *token = strtok(selectedCharsets_copy, ",，");
    while(token != NULL) {
        bool matched = false;
        for(size_t j = 0; j < NUM_CHARSETS; j++) {
            if(strcmp(token, CHARSETS[j].identifier) == 0) {
                strcat(combinedCharset, CHARSETS[j].characters);
                matched = true;
                break;
            }
        }
        if(!matched) { fprintf(stderr, "Error: Invalid charset identifier: %s\n", token); return 1; }
        token = strtok(NULL, ",，");
    }

    char uniqueCharset[4096] = {0};
    bool seen[256] = {false};
    int k = 0;
    for(int i = 0; combinedCharset[i] != '\0'; i++) {
        if (!seen[(unsigned char)combinedCharset[i]]) {
            seen[(unsigned char)combinedCharset[i]] = true;
            uniqueCharset[k++] = combinedCharset[i];
        }
    }
    uniqueCharset[k] = '\0';

    const char* finalCharset = uniqueCharset;
    int finalCharsetLength = strlen(finalCharset);

    if(finalCharsetLength == 0) { fprintf(stderr, "Error: Invalid charset selection!\n"); return 1; }
    if(minLength <= 0 || maxLength <= 0 || minLength > maxLength || maxLength > MAX_PASSWORD_LENGTH) {
        fprintf(stderr, "Error: Invalid length range! Length must be between 1 and %d.\n", MAX_PASSWORD_LENGTH);
        return 1;
    }

    FILE *output = stdout;
    if(outputFile != NULL) {
        output = fopen(outputFile, "w");
        if(!output) { perror("Error opening output file"); return 1; }
    }
    
    infinite = (random && !n_specified);
    if (!random && n_specified) fprintf(stderr, "Warning: The -n option is ignored in sequential build mode.\n");

    auto start_time = std::chrono::high_resolution_clock::now();
    
    generateDictionary((u128)numPasswords_ll, minLength, maxLength, threads, random, output, finalCharset, finalCharsetLength, infinite);

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end_time - start_time;

    if(outputFile != NULL) fclose(output);
 
    return 0;
}
