#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

// 定义各个字符集
typedef struct {
    const char *identifier;
    const char *characters;
} Charset;

// 定义支持的字符集
const Charset CHARSETS[] = {
    {"d", "0123456789"},                                         // d | [0-9]
    {"u", "abcdefghijklmnopqrstuvwxyz"},                       // u | [a-z]
    {"i", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"},                       // i | [A-Z]
    {"h", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"},                                  // h | [0-9a-fA-Z]
    {"j", "0123456789ABCDEF"},                                  // j | [0-9A-F]
    {"k", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"},  // k | [a-zA-Z]
    {"s", " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"},                // s | 特殊字符
    {"all", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~"} // all | 所有字符
};

#define NUM_CHARSETS (sizeof(CHARSETS) / sizeof(CHARSETS[0]))
#define MAX_PASSWORD_LENGTH 256  // 最大密码长度

// 整数幂计算函数，避免使用浮点数的 pow 函数
long long int_pow(int base, int exp) {
    long long result = 1;
    for(int i = 0; i < exp; i++) {
        result *= base;
    }
    return result;
}

// 生成密码的结构体
typedef struct {
    long long startIndex;
    long long endIndex;
    int minLength;
    int maxLength;
    int random;
    FILE *file;
    pthread_mutex_t *mutex;
    const char *charset;
    int charsetLength;
    long long *cumulativeLengths; // 累积密码数，用于递增模式
    int infinite; // 标记是否为无限生成（随机模式）
} ThreadData;

// 索引到密码的映射函数（递增模式）
void index_to_password(long long index, char *password, int minLength, int maxLength, const char *charset, int charsetLength, long long *cumulativeLengths) {
    int length;
    for(length = minLength; length <= maxLength; length++) {
        if(index < cumulativeLengths[length - minLength +1]) {
            break;
        }
    }
    long long localIndex = index - cumulativeLengths[length - minLength];
    // 将 localIndex 转换为密码
    for(int i = length - 1; i >=0; --i){
        password[i] = charset[localIndex % charsetLength];
        localIndex /= charsetLength;
    }
    password[length] = '\0';
}

// 生成随机字符
char generateRandomChar(unsigned int *seed, const char *charset, int charsetLength) {
    return charset[rand_r(seed) % charsetLength];
}

// 随机生成一个密码
void generateRandomPassword(char *password, int length, unsigned int *seed, const char *charset, int charsetLength) {
    for(int i = 0; i < length; ++i) {
        password[i] = generateRandomChar(seed, charset, charsetLength);
    }
    password[length] = '\0';
}

// 线程生成密码的函数
void* generatePasswords(void* arg) {
    ThreadData *data = (ThreadData *)arg;
    unsigned int seed = time(NULL) ^ pthread_self();

    char password[MAX_PASSWORD_LENGTH +1];
    
    if(data->random) {
        // 随机模式，无限生成
        while(1) {
            int passwordLength = data->minLength;
            if(data->maxLength > data->minLength) {
                passwordLength += rand_r(&seed) % (data->maxLength - data->minLength +1);
            }
            generateRandomPassword(password, passwordLength, &seed, data->charset, data->charsetLength);

            // 写入输出
            pthread_mutex_lock(data->mutex);
            fprintf(data->file, "%s\n", password);
            pthread_mutex_unlock(data->mutex);
        }
    }
    else {
        // 递增模式，生成指定范围的密码
        for(long long idx = data->startIndex; idx < data->endIndex; ++idx) {
            // 递增生成密码
            index_to_password(idx, password, data->minLength, data->maxLength, data->charset, data->charsetLength, data->cumulativeLengths);

            // 写入输出
            pthread_mutex_lock(data->mutex);
            fprintf(data->file, "%s\n", password);
            pthread_mutex_unlock(data->mutex);
        }
    }

    return NULL;
}

// 生成字典的函数
void generateDictionary(long long numPasswords, int minLength, int maxLength, int threads, int random, FILE *file, const char *charset, int charsetLength, long long possiblePasswords, int infinite) {
    pthread_t *threadIds = new pthread_t[threads]; // 使用 new 替换 malloc
    if(!threadIds) {
        perror("内存分配失败");
        return;
    }

    ThreadData *threadData = new ThreadData[threads]; // 使用 new 替换 malloc
    if(!threadData) {
        perror("内存分配失败");
        delete[] threadIds; // 释放已分配内存
        return;
    }

    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;  // 文件操作的锁

    // 预计算每种长度的累积密码数（仅用于递增模式）
    long long *cumulativeLengths = NULL;
    if(!random && !infinite) {
        int numLengths = maxLength - minLength +1;
        cumulativeLengths = new long long[numLengths +1]; // 使用 new 替换 malloc
        if(!cumulativeLengths) {
            perror("内存分配失败");
            delete[] threadIds;
            delete[] threadData;
            return;
        }
        cumulativeLengths[0] =0;
        for(int len = minLength; len <= maxLength; len++) {
            cumulativeLengths[len - minLength +1] = cumulativeLengths[len - minLength] + int_pow(charsetLength, len);
        }
    }

    // 分配给每个线程的密码数量
    for(int i = 0; i < threads; ++i) {
        if(!random && !infinite) {
            long long passwordsPerThread = numPasswords / threads;
            long long remaining = (i == threads -1) ? (numPasswords - passwordsPerThread *i) : passwordsPerThread;

            threadData[i].startIndex = i * passwordsPerThread;
            threadData[i].endIndex = threadData[i].startIndex + remaining;
            threadData[i].cumulativeLengths = cumulativeLengths;
        }
        else {
            // 随机模式或无限递增模式
            threadData[i].startIndex =0;
            threadData[i].endIndex =0; // 不使用
            threadData[i].cumulativeLengths = NULL;
        }

        threadData[i].minLength = minLength;
        threadData[i].maxLength = maxLength;
        threadData[i].random = random;
        threadData[i].file = file;
        threadData[i].mutex = &mutex;
        threadData[i].charset = charset;
        threadData[i].charsetLength = charsetLength;
        threadData[i].infinite = infinite;

        if(pthread_create(&threadIds[i], NULL, generatePasswords, &threadData[i]) !=0) {
            perror("线程创建失败");
            // 释放资源
            for(int j=0; j <i; ++j) {
                pthread_cancel(threadIds[j]);
                pthread_join(threadIds[j], NULL);
            }
            delete[] threadIds;
            delete[] threadData;
            if(cumulativeLengths) delete[] cumulativeLengths;
            return;
        }
    }

    // 等待所有线程完成（在随机模式下，这些线程将无限运行，程序需要手动停止）
    for(int i =0; i < threads; ++i) {
        pthread_join(threadIds[i], NULL);
    }

    delete[] threadIds; // 释放已分配的内存
    delete[] threadData; // 释放已分配的内存
    if(cumulativeLengths) delete[] cumulativeLengths; // 释放已分配的内存
}

// 解析长度范围（例如 3-4）并返回 minLength 和 maxLength
void parseLengthRange(char *range, int *minLength, int *maxLength) {
    char *dashPos = strchr(range, '-');
    if(dashPos) {
        *dashPos = '\0';  // 切割成两部分
        *minLength = atoi(range);
        *maxLength = atoi(dashPos +1);
    }
    else {
        // 如果没有 `-`，假定只有一个数字
        *minLength = *maxLength = atoi(range);
    }
}

// 打印帮助信息
void printHelp() {
    printf("Usage: wandian [-n num] [-t threads] [-l length] [-c charset] [-R] [-o outputFile]\n");
    printf("  -n num           : Number of passwords to generate (only valid with -o)\n");
    printf("  -t threads       : Number of threads to use (default: 4)\n");
    printf("  -l length        : Password length range (e.g., 3-4)\n");
    printf("  -c charset       : Character sets to use (e.g., d,u,i,h,j,k,s,all)\n");
    printf("                     Multiple sets can be separated by commas, e.g., -c d,u,i\n");
    printf("  -R               : Random password generation (generate indefinitely)\n");
    printf("  -o outputFile    : Output file name (only valid with -n)\n");
}

int main(int argc, char *argv[]) {
    long long numPasswords = 10000; // 默认生成一万个密码
    int minLength = 8;
    int maxLength = 9;
    int threads = 1;  // 默认线程数为4
    int random = 0;   // 默认递增模式
    char *outputFile = NULL; // 默认输出到控制台
    char selectedCharsets[1024] = {0}; // 存储用户选择的字符集标识
    const char *finalCharset = NULL;
    int finalCharsetLength = 0;
    int n_specified = 0; // 标记是否指定了 -n

    // 解析命令行参数
    for(int i =1; i < argc; i++) {
        if(strcmp(argv[i], "-R") ==0) {
            random =1;  // 开启随机生成模式
        }
        else if(strcmp(argv[i], "-t") ==0) {
            if(i +1 < argc) {
                threads = atoi(argv[++i]); // 设置线程数
                if(threads <=0) {
                    printf("无效的线程数！\n");
                    return 1;
                }
            }
            else {
                printHelp();
                return 1;
            }
        }
        else if(strcmp(argv[i], "-n") ==0) {
            if(i +1 < argc) {
                numPasswords = atoll(argv[++i]); // 设置生成的密码数量
                if(numPasswords <=0) {
                    printf("无效的密码数量！\n");
                    return 1;
                }
                n_specified =1;
            }
            else {
                printHelp();
                return 1;
            }
        }
        else if(strcmp(argv[i], "-o") ==0) {
            if(i +1 < argc) {
                outputFile = argv[++i]; // 设置输出文件
            }
            else {
                printHelp();
                return 1;
            }
        }
        else if(strcmp(argv[i], "-l") ==0) {
            if(i +1 < argc) {
                parseLengthRange(argv[++i], &minLength, &maxLength);
                if(minLength <=0 || maxLength <=0 || minLength > maxLength) {
                    printf("无效的密码长度范围！\n");
                    return 1;
                }
            }
            else {
                printHelp();
                return 1;
            }
        }
        else if(strcmp(argv[i], "-c") ==0) {
            if(i +1 < argc) {
                strncpy(selectedCharsets, argv[++i], sizeof(selectedCharsets) -1);
            }
            else {
                printHelp();
                return 1;
            }
        }
        else {
            printHelp();
            return 1;
        }
    }

    // 检查 -n 是否与 -o 同时存在
    if(n_specified && outputFile == NULL && !random) {
        printf("错误：-n 参数只能与 -o 参数一起使用。\n");
        return 1;
    }

    // 检查 -n 是否与 -R 同时存在
    if(n_specified && random) {
        printf("错误：-n 参数不能与 -R 参数一起使用。\n");
        return 1;
    }

    // 如果没有指定字符集，默认使用 'all'
    if(strlen(selectedCharsets) ==0) {
        strcpy(selectedCharsets, "all");
    }

    // 构建最终的字符集
    char combinedCharset[4096] = {0};
    char *token = strtok(selectedCharsets, ",，");
    
    while(token != NULL) {
        int matched =0;
        for(int j =0; j < NUM_CHARSETS; j++) {
            if(strcmp(token, CHARSETS[j].identifier) ==0) {
                strcat(combinedCharset, CHARSETS[j].characters);
                matched =1;
                break;
            }
        }
        if(!matched) {
            printf("无效的字符集标识: %s\n", token);
            return 1;
        }
        token = strtok(NULL, ",，");
    }

    // 移除重复字符
    char uniqueCharset[4096] = {0};
    for(int i =0; combinedCharset[i] !='\0'; i++) {
        if(strchr(uniqueCharset, combinedCharset[i]) == NULL) {
            strncat(uniqueCharset, &combinedCharset[i],1);
        }
    }

    finalCharset = uniqueCharset;
    finalCharsetLength = strlen(finalCharset);

    // 检查是否有选择的字符集
    if(finalCharsetLength ==0) {
        printf("无效的字符集选择！\n");
        return 1;
    }

    // 设置输出目标
    FILE *output = stdout; // 默认输出到控制台
    FILE *fileToClose = NULL; // 如果输出到文件，记录需要关闭的文件指针

    if(outputFile != NULL) {
        fileToClose = fopen(outputFile, "w");
        if(!fileToClose) {
            perror("无法打开输出文件");
            return 1;
        }
        output = fileToClose;
    }

    // 计算总可能密码数（仅在递增模式下）
    long long possiblePasswords =0;
    long long *cumulativeLengths = NULL;
    int infinite =0;

    if(!random) {
        // 预计算累积密码数
        cumulativeLengths = new long long[maxLength - minLength +1 +1]; // 使用 new 替换 malloc
        if(!cumulativeLengths) {
            perror("内存分配失败");
            if(fileToClose) fclose(fileToClose);
            return 1;
        }
        cumulativeLengths[0] =0;
        for(int len = minLength; len <= maxLength; len++) {
            cumulativeLengths[len - minLength +1] = cumulativeLengths[len - minLength] + int_pow(finalCharsetLength, len);
        }

        // 计算总可能密码数
        for(int len = minLength; len <= maxLength; len++) {
            possiblePasswords += int_pow(finalCharsetLength, len);
        }

        if(n_specified) {
            // 指定了 -n 和 -o，检查是否超过可能数量
            if(numPasswords > possiblePasswords) {
                printf("递增模式下，生成的密码数量 (%lld) 超过了可能的密码数量 (%lld)！\n", numPasswords, possiblePasswords);
                delete[] cumulativeLengths;
                if(fileToClose) fclose(fileToClose);
                return 1;
            }
        }
        else {
            if(outputFile == NULL) {
                // 未指定 -o，忽略 -n，生成所有可能的密码
                numPasswords = possiblePasswords;
            }
            // 如果指定了 -o，但未指定 -n，则生成所有可能的密码
        }
    }
    else {
        // 随机模式，无需计算 possiblePasswords
        infinite =1;
    }

    // 生成字典
    generateDictionary(numPasswords, minLength, maxLength, threads, random, output, finalCharset, finalCharsetLength, possiblePasswords, infinite);

    // 如果指定了输出文件，显示提示信息
    if(outputFile != NULL && !random) {
        fclose(fileToClose);
        printf("字典生成完毕，生成了 %lld 个密码，保存在 %s 文件中！\n", numPasswords, outputFile);
    }
    else if(outputFile != NULL && random) {
        // 随机模式下，提示用户程序正在运行
        printf("随机密码生成已开始，输出到 %s 文件中。按 Ctrl+C 停止。\n", outputFile);
    }

    // 释放累积密码数的内存
    if(cumulativeLengths) {
        delete[] cumulativeLengths;
    }

    return 0;
}
