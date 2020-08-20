#include "ui.h"

void showValueTypeMenu(char *userInput, char *searchType, VALUE_TYPE *valueType) {
    printf("== Choice of value type ===\n");
    printf("[a] - one byte (char)\n");
    printf("[b] - two byte (short)\n");
    printf("[c] - four byte (int)\n");
    printf("[d] - float\n");
    printf("[e] - double\n");
    printf("[f] - string\n");
    printf("Your choice: ");
    readString(userInput, MAX_CHAR_SIZE);

    switch(userInput[0]) {
        case 'a':
            *valueType = _ONE_BYTE;
            strcpy(searchType, "one byte");
            break;
        case 'b':
            *valueType = _TWO_BYTE;
            strcpy(searchType, "two byte");
            break;
        case 'c':
            *valueType = _FOUR_BYTE;
            strcpy(searchType, "four byte");
            break;
        case 'd':
            *valueType = _FLOAT;
            strcpy(searchType, "float");
            break;
        case 'e':
            *valueType = _DOUBLE;
            strcpy(searchType, "double");
            break;
        default:
            *valueType = _STRING;
            strcpy(searchType, "string");
            break;
    }
}

void showMatchMenu(MEMBLOCK **scan, char *userInput, VALUE_TYPE *valueType, double *val, SEARCH_CONDITION *cond, DWORD *pid, MENU *uiMenu) {
    printf("=== %d matches found ===\n", getMatchesCount(*scan));
    printf("[a] - print matches\n");
    printf("[b] - increased value\n");
    printf("[c] - decreased value\n");
    printf("[d] - new scan\n");
    printf("[e] - change pid\n");
    printf("[f] - write to an address\n");
    printf("[q] - quit\n");
    printf("or Enter new exact value\n");
    printf("Your input: ");
    readString(userInput, MAX_CHAR_SIZE);

    switch(userInput[0]) {
        case 'a':
            print_matches(*scan, *valueType);
            break;
        case 'b':
            *cond = COND_INCREASED;
            updateScan(*scan, *cond, *val, *valueType);
            break;
        case 'c':
            *cond = COND_DECREASED;
            updateScan(*scan, *cond, *val, *valueType);
            break;
        case 'd':
            freeScan(*scan);
            *scan = createScan(*pid);
            *uiMenu = SEARCH_VALUE_MENU;
            break;
        case 'e':
            freeScan(*scan);
            enterPid(scan, pid);
            *uiMenu = MAIN_MENU;
            break;
        case 'f':
            *uiMenu = WRITE_MENU;
            break;
        case 'q':
            printf("Goodbye! Thank you.\n");
            *uiMenu = EXIT_MENU;
            freeScan(*scan);
            break;
        default:
            *cond = COND_EQUALS;
            *val = strtol(userInput, NULL, 10);
            updateScan(*scan, *cond, *val, *valueType);
            break;
    }
}

void showWriteMenu(double *val, MEMBLOCK *scan, LPVOID addrToWrite, char *userInput, char *searchType, VALUE_TYPE *valueType, MENU *uiMenu) {
    showValueTypeMenu(userInput, searchType, valueType);
    printf("Enter the adress to write: ");
    scanf("%x", addrToWrite);
    clearStringBuffer();
    printf("== writing a %s to 0x%x ==\n", searchType, addrToWrite);
    printf("Value: ");
    scanf("%lf", val);
    clearStringBuffer();
    write(scan->hProc, *valueType, addrToWrite, *val);
    *uiMenu = MAIN_MENU;
}

void showSearchValueMenu(char *userInput, char *searchType, VALUE_TYPE *valueType, MENU *uiMenu, SEARCH_CONDITION *cond, double *val, MEMBLOCK* scan) {
    showValueTypeMenu(userInput, searchType, valueType);
    printf("=== %s searching ===\n", searchType);
    printf("Enter exact value or [u] for unknown value: ");
    readString(userInput, MAX_CHAR_SIZE);

    if(userInput[0] == 'u') {
        *cond = COND_UNCONDITIONAL;
    } else {
        *cond = COND_EQUALS;
        *val = strtod(userInput, NULL);
    }
    updateScan(scan, *cond, *val, *valueType);
    *uiMenu = MATCH_MENU;

}

void showMainMenu(MEMBLOCK *scan, DWORD *pid, char *userInput, MENU *uiMenu) {
    printf("== Main menu (PID=%d) ==\n", *pid);
    printf("[r] - read\n");
    printf("[w] - write\n");
    printf("[c] - change PID\n");
    printf("[q] - quit\n");
    printf("Your choice: ");
    readString(userInput, MAX_CHAR_SIZE);

    if(userInput[0] == 'q') {
        return;
    } else if(userInput[0] == 'r') {
        *uiMenu = SEARCH_VALUE_MENU;
    } else if(userInput[0] == 'c') {
        freeScan(scan);
        enterPid(&scan, pid);
    } else if(userInput[0] == 'w') {
        *uiMenu = WRITE_MENU;
    }

}