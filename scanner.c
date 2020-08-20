#include "scanner.h"

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege ) {
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

double read(HANDLE hProc, VALUE_TYPE valueType, LPCVOID addr) {
    double val = 0;
    int data_size = getDataSize(valueType);

    if(ReadProcessMemory(hProc, addr, &val, data_size, NULL) == 0) {
        printf("read failed\n");
    }

    return val;
}

void write(HANDLE hProc, VALUE_TYPE valueType, LPVOID addr, double val) {
    int data_size = getDataSize(valueType);

    switch(valueType) {
        case _ONE_BYTE: ;
            char charVal = (char) val;
            if(WriteProcessMemory(hProc, addr, &charVal, data_size, NULL) == 0) printf("Writing failed\n");
            break;
        case _TWO_BYTE: ;
            short shortVal = (short) val;
            if(WriteProcessMemory(hProc, addr, &shortVal, data_size, NULL) == 0) printf("Writing failed\n");
            break;
        case _FOUR_BYTE: ;
            int intVal = (int) val;
            if(WriteProcessMemory(hProc, addr, &intVal, data_size, NULL) == 0) printf("Writing failed\n");
            break;
        case _EIGHT_BYTE: ;
            long longVal = (long) val;
            if(WriteProcessMemory(hProc, addr, &longVal, data_size, NULL) == 0) printf("Writing failed\n");
            break;
        case _FLOAT: ;
            float floatVal = (float) val;
            if(WriteProcessMemory(hProc, addr, &floatVal, data_size, NULL) == 0) printf("Writing failed\n");
            break;
        case _STRING: ;
            break;
        default:
            if(WriteProcessMemory(hProc, addr, &val, data_size, NULL) == 0) printf("Writing failed\n");
            break;
    }
}

MEMBLOCK* createMemblock (HANDLE hProc, MEMORY_BASIC_INFORMATION *meminfo) {
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

void freeMemblock (MEMBLOCK *mb) {
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

void updateMemblock(MEMBLOCK *mb, SEARCH_CONDITION condition, double val, VALUE_TYPE valueType) {
    // We'll read content in block of 128K
    char tempbuf[128*1024];
    unsigned int bytes_left;
    unsigned int total_read;
    SIZE_T bytes_to_read;
    // Store the number of bytes transferred into the buffer by reading
    SIZE_T bytes_read;

    if(mb->matches > 0) {
        bytes_left = mb->size;
        total_read = 0;
        // Cause we haven't found any in this new 
        mb->matches = 0;

        while(bytes_left)
        {
            bytes_to_read = (bytes_left > sizeof(tempbuf)) ? sizeof(tempbuf) : bytes_left;
            ReadProcessMemory(mb->hProc, (mb->addr + total_read), tempbuf, bytes_to_read, &bytes_read);
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

MEMBLOCK* createScan(unsigned int pid) {
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
                MEMBLOCK * mb = createMemblock(hProc, &meminfo);
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

void freeScan (MEMBLOCK* mb_list) {
    // Close the handle to the process we opened with OpenProcess
    CloseHandle(mb_list->hProc);  
    // We loop through the linked list and free each memblock as long it's not null
    while(mb_list)
    {
        MEMBLOCK *mb = mb_list;
        mb_list = mb_list->next;
        freeMemblock(mb);
    }
}

void updateScan(MEMBLOCK* mb_list, SEARCH_CONDITION condition, double val, VALUE_TYPE valueType) {
    MEMBLOCK *mb = mb_list;

    while(mb) {
        updateMemblock(mb, condition, val, valueType);
        mb = mb->next;
    }
}

int getMatchesCount(MEMBLOCK *mb_list) {
    MEMBLOCK *mb = mb_list;
    unsigned int count = 0;

    while(mb) {
        count += mb->matches;
        mb = mb->next;
    }

    return count;
}

void enterPid(MEMBLOCK **scan, DWORD *pid) {
    while(1) {
        printf("Enter pid: ");
        scanf("%d", pid);
        clearStringBuffer();
        printf("pid = %d\n", *pid);
        *scan = createScan(*pid);
        if(*scan) break;
    }
}