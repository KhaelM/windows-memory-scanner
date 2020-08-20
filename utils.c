#include "utils.h"

void clearStringBuffer() {
    int c = 0;
    while (c != '\n' && c != EOF)
    {
        c = getchar();
    }
}

int readString(char *str, int length) {
    char *backspacePosition = NULL;
 
    if (fgets(str, length, stdin) != NULL)
    {
        backspacePosition = strchr(str, '\n');
        if (backspacePosition != NULL)
        {
            *backspacePosition = '\0';
        }
        else
        {
            clearStringBuffer();
        }
        return 1;
    }
    else
    {
        clearStringBuffer();
        return 0;
    }
}

unsigned int strToAddress(char *str) {
    int base = 10;

    if(str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        base = 16;
        str += 2;
    }

    return strtoul(str, NULL, base);
}