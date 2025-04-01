#include <Windows.h>

// -------------------- Macro's -------------------- 
// printf CRT replacement
#define PRINTA( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }

// getchar() replacement
#define WAIT_FOR_ENTER()                          \
    do {                                          \
        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE); \
        DWORD mode;                               \
        GetConsoleMode(hIn, &mode);               \
        SetConsoleMode(hIn, mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT)); \
        char ch = 0; DWORD read;                  \
        ReadFile(hIn, &ch, 1, &read, NULL);       \
        SetConsoleMode(hIn, mode);                \
    } while(0)


// --------------------  Definitions -------------------- 
BOOL FluctuateShellcode(IN PBYTE pShellcodeBuffer, IN DWORD dwSize);
LPVOID GetShellcodeBaseAddress(HANDLE hProc, DWORD szPage, DWORD szAllocGran, DWORD cVmResv);
unsigned char* ReadShellcode(const char* fileName, DWORD * dwSize);
void* MoveMem(void* dest, const void* src, unsigned int count);


