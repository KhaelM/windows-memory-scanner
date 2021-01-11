#include "ui.h"

int main(int argc, char *argv[])
{
    printf("****** Memory Scanner by Michael Randrianarisona ******\n");
    // get process handle
    // HANDLE hProc = GetCurrentProcess();

    // // get access token of process
    // HANDLE hToken = NULL;
    // if (!OpenProcessToken(hProc, TOKEN_ADJUST_PRIVILEGES, &hToken))
    //      printf ("Failed to open access token");

    // // set token privileges to SE_DEBUG_NAME to able to access OpenProcess() with PROCESS_ALL_ACCESS
    // if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
    //     printf ("Failed to set debug privilege");
    DWORD pid;
    char userInput[20];
    MEMBLOCK *scan = NULL;
    VALUE_TYPE valueType;
    double val;
    char searchType[10];
    SEARCH_CONDITION cond;
    MENU ui = MAIN_MENU;
    LPVOID addrToWrite = 0;

    enterPid(&scan, &pid);

    while(ui != EXIT_MENU) {
        if(ui == MAIN_MENU)
            showMainMenu(scan, &pid, userInput, &ui);
        else if(ui == SEARCH_VALUE_MENU)
            showSearchValueMenu(userInput, searchType, &valueType, &ui, &cond, &val, scan);
        else if(ui == WRITE_MENU)
            showWriteMenu(&val, scan, addrToWrite, userInput, searchType, &valueType, &ui);
        else if(ui == MATCH_MENU)
            showMatchMenu(&scan, userInput, &valueType, &val, &cond, &pid, &ui);
    }

    freeScan(scan);
    return 0;
}