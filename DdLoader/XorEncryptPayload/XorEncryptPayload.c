#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

typedef unsigned char BYTE;
typedef unsigned char* PBYTE;
typedef size_t SIZE_T;

#define XOR_KEY 0x41  // Hardcoded XOR key

VOID XorByiKeys(PBYTE buf, SIZE_T size, BYTE bKey) {
    for (size_t i = 0; i < size; i++) {
        buf[i] = buf[i] ^ (bKey + i);
    }
}

int main() {
    const char* input_filename = "beacon.bin";
    const char* output_filename = "PAYLOAD.bin";

    FILE* infile = fopen(input_filename, "rb");
    if (!infile) {
        perror("[-] Failed to open input file");
        return 1;
    }

    // Get file size
    fseek(infile, 0, SEEK_END);
    SIZE_T size = ftell(infile);
    fseek(infile, 0, SEEK_SET);

    // Allocate buffer
    PBYTE buffer = (PBYTE)malloc(size);
    if (!buffer) {
        perror("[-] Memory allocation failed");
        fclose(infile);
        return 1;
    }

    // Read file into buffer
    if (fread(buffer, 1, size, infile) != size) {
        perror("[-] Failed to read input file");
        free(buffer);
        fclose(infile);
        return 1;
    }
    fclose(infile);

    // Encrypt buffer
    XorByiKeys(buffer, size, XOR_KEY);

    // Write encrypted buffer to output file
    FILE* outfile = fopen(output_filename, "wb");
    if (!outfile) {
        perror("[-] Failed to open output file");
        free(buffer);
        return 1;
    }

    if (fwrite(buffer, 1, size, outfile) != size) {
        perror("[-] Failed to write to output file");
        free(buffer);
        fclose(outfile);
        return 1;
    }

    printf("[+] Encrypted data written to %s (%zu bytes)\n", output_filename, size);

    free(buffer);
    fclose(outfile);
    return 0;
}
