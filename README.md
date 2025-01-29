# Wandian - Multithreaded Password Dictionary Generator

Wandian is a high-performance and feature-rich password dictionary generator written in C. Designed to meet various password generation needs, Wandian supports multiple character sets, allows for sequential (incremental) and random password generation, and utilizes multithreading to maximize generation efficiency. Whether you need to generate a limited list of passwords or an infinite stream for testing, Wandian can meet your requirements.

## Features

- **Multiple Character Sets**: Choose from predefined character sets or combine them to suit your needs.
- **Sequential and Random Generation**: Generate passwords in a sequential (incremental) manner or randomly.
- **Multithreading**: Utilize multiple CPU cores to accelerate the password generation process.
- **Customizable Length**: Specify the minimum and maximum length of passwords.
- **Flexible Output**: Output passwords to the console or directly write them to a file.
- **Infinite Generation Mode**: Optionally generate passwords infinitely in random mode.
- **Efficient Memory Usage**: Optimized to handle large-scale password generation without excessive memory consumption.

## Installation

### Prerequisites

- **C Compiler**: Ensure a C compiler is installed (e.g., `gcc`).
- **POSIX Threads Library**: Requires multithreading support.

### Compile Source Code

```bash
gcc -o wandian wandian.c -lpthread
```

This command compiles the `wandian.c` source file and links the POSIX threads library (`-lpthread`), generating an executable named `wandian`.

## Usage

Wandian operates through a Command Line Interface (CLI), offering various options to customize password generation.

### Command Line Options

```
Usage: wandian [-n num] [-t threads] [-l length] [-c charset] [-R] [-o outputFile]

  -n num           : Number of passwords to generate (effective only with -o)
  -t threads       : Number of threads to use (default: 4)
  -l length        : Password length range (e.g., 3-4)
  -c charset       : Character set to use (e.g., d,u,i,h,j,k,s,all)
                     Multiple sets can be separated by commas, e.g., -c d,u,i
  -R               : Random password generation (infinite generation)
  -o outputFile    : Output file name (effective only with -n)
```

### Option Descriptions

- **-n num**: Specifies the number of passwords to generate. Must be used with `-o`.
- **-t threads**: Determines the number of concurrent threads to use. Defaults to 4 if not specified.
- **-l length**: Sets the password length range. Accepts formats like `1-12` to generate passwords between 1 and 12 characters long.
- **-c charset**: Defines the character set used for password generation. Multiple sets can be combined using commas.
- **-R**: Activates random password generation mode, continuously generating passwords until manually stopped.
- **-o outputFile**: Specifies the file name to which generated passwords will be written. Must be used with `-n`.

### Character Set Identifiers

- **d**: Numbers `[0-9]`
- **u**: Lowercase letters `[a-z]`
- **i**: Uppercase letters `[A-Z]`
- **h**: Hexadecimal lowercase `[0-9a-f]`
- **j**: Hexadecimal uppercase `[0-9A-F]`
- **k**: Both lowercase and uppercase letters `[a-zA-Z]`
- **s**: Special characters `[ !"#$%&'()*+,-./:;<=>?@[\]^_{|}~]`
- **all**: All available characters

## Examples

### 1. Generate 100,000 Passwords

```bash
./wandian -n 100000 -t 8 -l 7-8 -c d,j -o passwords.txt
```

**Description**: Generates 100,000 passwords with lengths between 7 and 8 characters using numbers and uppercase hexadecimal characters, utilizing 8 threads, and writes the output to `passwords.txt`.

### 2. Infinite Random Password Generation Mode

```bash
./wandian -R -t 4 -l 10 -c all -o random_passwords.txt
```

**Description**: Continuously generates random passwords of length 10 using all character sets, utilizing 4 threads, and outputs to `random_passwords.txt`. Press `Ctrl+C` to stop.

### 3. Generate All Possible Passwords Without Specifying an Output File

```bash
./wandian -l 3-4 -c d
```
**Or**

```bash
./wandian -l 3-4 -c d > passwords.txt
```

**Description**: Generates all possible numeric passwords between 3 and 4 digits. The first command prints them to the console using the default 4 threads, while the second command saves them to `passwords.txt`.

### 4. Combining Character Sets for Advanced Use

```bash
./wandian -l 64 -c j -R | ./brainflayer -v -b hash160.blf -f hash160.bin -t priv -x -c uce > key.txt
```

**Description**: Generates random 64-character passwords (e.g., BTC, ETH, etc.), pipes them to `brainflayer` for processing, and outputs the results to `key.txt`.

**Note**: Without `-R`, the program operates in incremental mode, supporting password lengths up to 20 characters. For lengths beyond 13-20 characters, use `-R` mode, which supports up to 256 characters.

## Predefined Character Sets

| Identifier | Characters                                    | Description                         |
|------------|-----------------------------------------------|-------------------------------------|
| d          | `0123456789`                                  | Numbers `[0-9]`                     |
| u          | `abcdefghijklmnopqrstuvwxyz`                  | Lowercase letters `[a-z]`           |
| i          | `ABCDEFGHIJKLMNOPQRSTUVWXYZ`                  | Uppercase letters `[A-Z]`           |
| h          | `0123456789abcdef`                            | Hexadecimal lowercase `[0-9a-f]`    |
| j          | `0123456789ABCDEF`                            | Hexadecimal uppercase `[0-9A-F]`    |
| k          | `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ` | Both lowercase and uppercase letters `[a-zA-Z]` |
| s          | `!"#$%&'()*+,-./:;<=>?@[\]^_{|}~`            | Special characters                  |
| all        | ``abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{} ;:'",.<>?/~`` | All available characters            |

### Combining Character Sets

To create a custom character set, list the desired identifiers separated by commas. For example:

- `-c d,u,i`: Combines numbers, lowercase letters, and uppercase letters.
- `-c h,j,s`: Combines hexadecimal (both cases) and special characters.
- `-c all`: Includes all available characters.

**Note**: Duplicate characters across multiple sets are automatically removed, ensuring each character in the final set is unique.

## Purpose

Parses user-provided command line arguments to configure password generation parameters.

## Program Flow

1. **Parameter Parsing**: The `main` function first parses command line arguments to determine generation parameters such as the number of passwords, number of threads, length range, character set, random mode, and output file.
2. **Character Set Construction**: Based on user input, the final character set is built, ensuring character uniqueness.
3. **Validation**: Checks for conflicting or invalid configurations, such as specifying `-n` without `-o` or combining `-n` with random mode.
4. **Password Generation**: Depending on the mode (sequential or random), calculates necessary parameters and starts multithreaded password generation using the `generateDictionary` function.
5. **Output**: Writes the generated passwords to the specified output file or the console.
6. **Cleanup**: Ensures all resources are released and files are properly closed.

## Contributing

Contributions are welcome! If you encounter issues or have improvement suggestions, feel free to submit an issue or pull request.

## Sponsorship

If this project has been helpful to you, please consider sponsoring. It is the greatest support for me, and I am deeply grateful. Thank you.

- **BTC**: bc1qt3nh2e6gjsfkfacnkglt5uqghzvlrr6jahyj2k
- **ETH**: 0xD6503e5994bF46052338a9286Bc43bC1c3811Fa1
- **DOGE**: DTszb9cPALbG9ESNJMFJt4ECqWGRCgucky
- **TRX**: TAHUmjyzg7B3Nndv264zWYUhQ9HUmX4Xu4

## License

This project is licensed under the MIT License.

## Disclaimer

This tool is intended for educational and research purposes only. Users are responsible for any risks and liabilities arising from the use of this tool. The developers are not liable for any losses resulting from the use of this tool.
