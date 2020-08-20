#include <Windows.h>
#include <stdio.h>
#include <string.h>

/**
 * This macro will allow us to test if a byte has his corresponding flag
 * mb->searchmask[(offset)/8] will find which of the groups
 * of 8 bits this offset corresponds to
 * eg: we ll' search byte 20 in the buffer
 * so mb->searchmask[2] & 1 << 4 
 * it means it will search whether the fourth byte of mb->searchmask[2] is 1 
*/
#define IS_IN_SEARCH(mb, offset) ( mb->searchmask[(offset)/8] & ( 1<<((offset)%8) ) )
/**
 * This macro will clear the 1 in the searchmask byte and turns it into 0
*/
#define REMOVE_FROM_SEARCH(mb, offset) mb->searchmask[(offset)/8] &= ~(1<<((offset)%8));

#define MAX_CHAR_SIZE 20 

typedef enum
{
    // When we don't want to discard any bytes
    COND_UNCONDITIONAL,

    // When we want to include a byte in the search
    // if it matches a particular value
    COND_EQUALS,

    // Only includes bytes in the search if
    // value has increase or decreased from the last search
    COND_INCREASED,
    COND_DECREASED
} SEARCH_CONDITION;

typedef enum
{
    MAIN_MENU,
    SEARCH_VALUE_MENU,
    MATCH_MENU,
    WRITE_MENU,
    EXIT_MENU
} MENU;

typedef enum
{
    _ONE_BYTE,
    _TWO_BYTE,
    _FOUR_BYTE,
    _EIGHT_BYTE,
    _FLOAT,
    _DOUBLE,
    _STRING
} VALUE_TYPE;

typedef struct _MEMBLOCK 
{
    HANDLE hProc;
    // base address related to this memblock
    unsigned char *addr;
    // size of the block aka how much memory there is beginning of the base address 
    int size;
    // local buffer where we'll store data from rpm
    unsigned char *buffer;

    /**
     * It's another buffer which holds A flag for every byte in << buffer >>
     * and THE flag decides wheter the byte should still be included
     * in the search. At the START we would search every single byte so EVERY
     * FLAG WOULD BE SET. Then for All the bytes that didn't match our first
     * search, we will clear their flags and we will loop this method.
     * This will contains ONLY BIT of TRUE or FALSE
    */
    unsigned char *searchmask;
    // Store how many matches are still in the memblock
    int matches;
    /**
     * This can be 1, 2 or 4 bytes
     * We use this member to decide whether the 
     * search comparisons should be done
     * on a byte basis(1 byte) , WORD basis(2 bytes), or DWORD basis(4 bytes)
    */
    struct _MEMBLOCK *next;
} MEMBLOCK;

BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
    )
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if ( !LookupPrivilegeValue(
			NULL,            // lookup privilege on local system
			lpszPrivilege,   // privilege to lookup
			&luid ) )        // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError() );
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if ( !AdjustTokenPrivileges(
		   hToken,
		   FALSE,
		   &tp,
		   sizeof(TOKEN_PRIVILEGES),
		   (PTOKEN_PRIVILEGES) NULL,
		   (PDWORD) NULL) )
	{
		  printf("AdjustTokenPrivileges error: %u\n", GetLastError() );
		  return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		  printf("The token does not have the specified privilege. \n");
		  return FALSE;
	}

	return TRUE;
}

void clearStringBuffer()
{
    int c = 0;
    while (c != '\n' && c != EOF)
    {
        c = getchar();
    }
}

int readString(char *str, int length)
{
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

int getDataSize(VALUE_TYPE valueType) {
    int data_size = 0;

    switch(valueType) {
        case _ONE_BYTE:
            data_size = 1;
            break;
        case _TWO_BYTE:
            data_size = 2;
            break;
        case _FOUR_BYTE:
            data_size = 4;
            break;
        case _EIGHT_BYTE:
            data_size = 8;
            break;
        case _FLOAT:
            data_size = sizeof(float);
            break;
        case _DOUBLE:
            data_size = sizeof(double);
            break;
    }

    return data_size;
}

double read(HANDLE hProc, VALUE_TYPE valueType, unsigned int addr) {
    double val = 0;
    int data_size = getDataSize(valueType);

    if(ReadProcessMemory(hProc, (LPCVOID)addr, &val, data_size, NULL) == 0) {
        printf("read failed\n");
    }

    return val;
}

void write(HANDLE hProc, VALUE_TYPE valueType, unsigned int addr, double val) {
    int data_size = getDataSize(valueType);

    switch(valueType) {
        case _ONE_BYTE: ;
            char charVal = (char) val;
            if(WriteProcessMemory(hProc, (void*)addr, &charVal, data_size, NULL) == 0) printf("Writing failed\n");
            break;
        case _TWO_BYTE: ;
            short shortVal = (short) val;
            if(WriteProcessMemory(hProc, (void*)addr, &shortVal, data_size, NULL) == 0) printf("Writing failed\n");
            break;
        case _FOUR_BYTE: ;
            int intVal = (int) val;
            if(WriteProcessMemory(hProc, (void*)addr, &intVal, data_size, NULL) == 0) printf("Writing failed\n");
            break;
        case _EIGHT_BYTE: ;
            long longVal = (long) val;
            if(WriteProcessMemory(hProc, (void*)addr, &longVal, data_size, NULL) == 0) printf("Writing failed\n");
            break;
        case _FLOAT: ;
            float floatVal = (float) val;
            if(WriteProcessMemory(hProc, (void*)addr, &floatVal, data_size, NULL) == 0) printf("Writing failed\n");
            break;
        case _STRING: ;
            break;
        default:
            if(WriteProcessMemory(hProc, (void*)addr, &val, data_size, NULL) == 0) printf("Writing failed\n");
            break;
    }
}

MEMBLOCK* create_memblock (HANDLE hProc, MEMORY_BASIC_INFORMATION *meminfo)
{
    MEMBLOCK *mb = malloc (sizeof(MEMBLOCK));

    if(mb)
    {
        mb->hProc = hProc;
        mb->addr = meminfo->BaseAddress;
        // RegionSize is the size of region(bytes) starting from baseAdrress
        mb->size = meminfo->RegionSize;
        // reserves enough memory to copy content on meminfo
        mb->buffer = malloc (meminfo->RegionSize);
        /**
         * We divide it by 8 cause we only need true or false value in this variable
         * for each byte of searchmask we can test each bit
        */ 
        mb->searchmask = malloc(meminfo->RegionSize/8);
        /**
         * We set every flag to true (FF = 1111 1111) for each byte
        */
        memset(mb->searchmask, 0xff, meminfo->RegionSize/8);
        // It's the number of bytes in the buffer
        mb->matches = meminfo->RegionSize;
        mb->next = NULL;
    }

    return mb;
}

void free_memblock (MEMBLOCK *mb)
{
    if(mb)
    {
        if(mb->buffer) {
            free(mb->buffer);
        }

        if(mb->searchmask) {
            free(mb->searchmask);
        }
        free(mb);
    }
}

void update_memblock(MEMBLOCK *mb, SEARCH_CONDITION condition, double val, VALUE_TYPE valueType)
{
    // We'll read content in block of 128K
    char tempbuf[128*1024];
    unsigned int bytes_left;
    unsigned int total_read;
    unsigned int bytes_to_read;
    // Store the number of bytes transferred into the buffer by reading
    unsigned int bytes_read;

    if(mb->matches > 0) {
        bytes_left = mb->size;
        total_read = 0;
        // Cause we haven't found any in this new 
        mb->matches = 0;

        while(bytes_left)
        {
            bytes_to_read = (bytes_left > sizeof(tempbuf)) ? sizeof(tempbuf) : bytes_left;
            ReadProcessMemory(mb->hProc, (LPCVOID) (mb->addr + total_read), tempbuf, bytes_to_read, (PDWORD) &bytes_read);
            if(bytes_read != bytes_to_read) break;

            if(condition == COND_UNCONDITIONAL) {
                memset(mb->searchmask + (total_read/8), 0xff, bytes_read/8);
                mb->matches += bytes_read;
            } else {
                /**
                 * We will loop through each byte in tempbuf
                */
                unsigned int offset;

                for(offset = 0; offset < bytes_read; offset++) {
                    if(IS_IN_SEARCH(mb, (total_read+offset))) {
                        BOOL is_match = FALSE;
                        double temp_val = 0;
                        double prev_val = 0;

                        switch (valueType) {
                            case _ONE_BYTE:
                                temp_val = tempbuf[offset];
                                prev_val = mb->buffer[total_read+offset];
                                break;
                            case _TWO_BYTE:
                                temp_val = *((short*) &tempbuf[offset]);
                                prev_val = *((short*) &mb->buffer[total_read+offset]);
                                break;
                            case _FOUR_BYTE:
                                temp_val = *((int*) &tempbuf[offset]);
                                prev_val = *((int*) &mb->buffer[total_read+offset]);
                                break;
                            case _EIGHT_BYTE:
                                temp_val = *((long*) &tempbuf[offset]);
                                prev_val = *((long*) &mb->buffer[total_read+offset]);
                                break;
                            case _FLOAT:
                                temp_val = *((float*) &tempbuf[offset]);
                                prev_val = *((float*) &mb->buffer[total_read+offset]);
                                break;
                            case _DOUBLE:
                                temp_val = *((double*) &tempbuf[offset]);
                                prev_val = *((double*) &mb->buffer[total_read+offset]);
                                break;
                            default:
                                temp_val = tempbuf[offset];
                                prev_val = mb->buffer[total_read+offset];
                                break;
                        }


                        switch(condition) {
                            case COND_EQUALS:
                                is_match = (temp_val == val);
                                break;
                            case COND_INCREASED:
                                is_match = (temp_val > prev_val);
                                break;
                            case COND_DECREASED:
                                is_match = (temp_val < prev_val);
                                break;
                            default:
                                break;
                        }

                        if(is_match) {
                            mb->matches++;
                            // printf("matched at 0x%08x\n", mb->addr + total_read + offset);
                        } else {
                            REMOVE_FROM_SEARCH(mb, (total_read+offset));
                        }
                    }
                }
            }

            memcpy (mb->buffer + total_read, tempbuf, bytes_read);

            bytes_left -= bytes_read;
            total_read += bytes_read; 
        }
        /* 
        * We do it just in case where there was a problem reading for example if there are some part of the memory that can't
        * be read 
        */
        mb->size = total_read;
    }
    
}

/**
 * Will return a mb pointer
 * which is the first element of the
 * linked list which represents the entire
 * memory contents of a process
*/
MEMBLOCK* create_scan(unsigned int pid)
{
    // First element for now but will be the last at the end
    MEMBLOCK *first_mb = NULL;
    // use this with VQEx
    MEMORY_BASIC_INFORMATION meminfo;
    // Address to keep track of the adress that we ll pass to VQEx
    unsigned char *addr = 0;

    // PROCESS_ALL_ACCESS to have super right on the process
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    DWORD error = GetLastError();

    if(hProc)
    {
         while(1)
         {
            /**
             * VQEx Functionment:
             * "addr" is where it will start
             * so here it will start with 0
             * and VQEx will return info based on an address
             * equal or higher than "addr" that is valid
             * and store it in meminfo
             * then we ll use the info on the next loop
            */
           // If VQEx fails it will be our condition to exit loop : when addr will be too high aka out of process adresses range
            if(VirtualQueryEx(hProc, addr, &meminfo, sizeof(meminfo)) == 0) {
                break;
            }

            /*
            * We take only block whose state have been commited (meminfo.State & MEM_COMMIT)
            * Which means they exist for real and not have just been
            * reserved for later use
            * 
            * AND
            * 
            * Only blocks that are not read-only
            * if just one the flag is set in Protect member then it's ok
            */
#define WRITABLE (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
            if((meminfo.State & MEM_COMMIT) && (meminfo.Protect & WRITABLE))
            {
                MEMBLOCK * mb = create_memblock(hProc, &meminfo);
                if(mb)
                {
                    // Makes the new mb the head of the linked list
                    mb->next = first_mb;
                    first_mb = mb;
                }
            }
            // We move our searchPoint to the end of the block
            // Next time addr will be the addr above current block
            // and eventually addr will be out of process memory block
            addr = (unsigned char*)meminfo.BaseAddress + meminfo.RegionSize;
         }
    }
    else {
        printf("Failed to open process : erro %d\n", error);
    }
    return first_mb;
}

void free_scan (MEMBLOCK* mb_list)
{
    // Close the handle to the process we opened with OpenProcess
    CloseHandle(mb_list->hProc);  
    // We loop through the linked list and free each memblock as long it's not null
    while(mb_list)
    {
        MEMBLOCK *mb = mb_list;
        mb_list = mb_list->next;
        free_memblock(mb);
    }
}

/**
 * will  the entire memblock
*/
void update_scan(MEMBLOCK* mb_list, SEARCH_CONDITION condition, double val, VALUE_TYPE valueType) {
    MEMBLOCK *mb = mb_list;

    while(mb) {
        update_memblock(mb, condition, val, valueType);
        mb = mb->next;
    }
}

void print_matches(MEMBLOCK *mb_list, VALUE_TYPE valueType) {
    unsigned int offset;
    MEMBLOCK *mb = mb_list;
    double val = 0;
    printf("\n=== Matches ===\n");
    while(mb) {
        for(offset = 0; offset < mb->size; offset++) {
            if(IS_IN_SEARCH(mb, offset)) {
                val = read(mb->hProc, valueType, (unsigned int)mb->addr + offset);
                if(valueType == _FLOAT || valueType == _DOUBLE)
                    printf("0x%08x (%f)\n", mb->addr + offset, val);
                else if(valueType == _STRING) 
                    printf("0x%08x (%s)\n", mb->addr + offset, val);
                else
                    printf("0x%08x (%d)\n", mb->addr + offset, val);
            }
        }
        mb = mb->next;
    }
}

int get_matches_count(MEMBLOCK *mb_list) {
    MEMBLOCK *mb = mb_list;
    unsigned int count = 0;

    while(mb) {
        count += mb->matches;
        mb = mb->next;
    }

    return count;
}

unsigned int strToAddress(char *str) {
    int base = 10;

    if(str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        base = 16;
        str += 2;
    }

    return strtoul(str, NULL, base);
}

void enterPid(MEMBLOCK **scan, DWORD *pid) {
    while(1) {
        printf("Enter pid: ");
        scanf("%d", pid);
        clearStringBuffer();
        printf("pid = %d\n", *pid);
        *scan = create_scan(*pid);
        if(*scan) break;
    }
}



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
    printf("=== %d matches found ===\n", get_matches_count(*scan));
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
            update_scan(*scan, *cond, *val, *valueType);
            break;
        case 'c':
            *cond = COND_DECREASED;
            update_scan(*scan, *cond, *val, *valueType);
            break;
        case 'd':
            free_scan(*scan);
            *scan = create_scan(*pid);
            *uiMenu = SEARCH_VALUE_MENU;
            break;
        case 'e':
            free_scan(*scan);
            enterPid(scan, pid);
            *uiMenu = MAIN_MENU;
            break;
        case 'f':
            *uiMenu = WRITE_MENU;
            break;
        case 'q':
            printf("Goodbye! Thank you.\n");
            *uiMenu = EXIT_MENU;
            free_scan(*scan);
            break;
        default:
            *cond = COND_EQUALS;
            *val = strtol(userInput, NULL, 10);
            update_scan(*scan, *cond, *val, *valueType);
            break;
    }
}

void showWriteMenu(double *val, MEMBLOCK *scan, unsigned int *addrToWrite, char *userInput, char *searchType, VALUE_TYPE *valueType, MENU *uiMenu) {
    showValueTypeMenu(userInput, searchType, valueType);
    printf("Enter the adress to write: ");
    scanf("%x", addrToWrite);
    clearStringBuffer();
    printf("== writing a %s to 0x%x ==\n", searchType, *addrToWrite);
    printf("Value: ");
    scanf("%lf", val);
    clearStringBuffer();
    write(scan->hProc, *valueType, *addrToWrite, *val);
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
    update_scan(scan, *cond, *val, *valueType);
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
        free_scan(scan);
        enterPid(&scan, pid);
    } else if(userInput[0] == 'w') {
        *uiMenu = WRITE_MENU;
    }

}

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
    unsigned int addrToWrite;

    enterPid(&scan, &pid);

    while(ui != EXIT_MENU) {
        if(ui == MAIN_MENU)
            showMainMenu(scan, &pid, userInput, &ui);
        else if(ui == SEARCH_VALUE_MENU)
            showSearchValueMenu(userInput, searchType, &valueType, &ui, &cond, &val, scan);
        else if(ui == WRITE_MENU)
            showWriteMenu(&val, scan, &addrToWrite, userInput, searchType, &valueType, &ui);
        else if(ui == MATCH_MENU)
            showMatchMenu(&scan, userInput, &valueType, &val, &cond, &pid, &ui);
    }

    free_scan(scan);
    return 0;
}

