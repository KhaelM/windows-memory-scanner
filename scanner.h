#pragma once

#include <Windows.h>
#include <stdio.h>
#include "utils.h"

BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
    );
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

typedef enum _SEARCH_CONDITION
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

typedef enum _MENU
{
    MAIN_MENU,
    SEARCH_VALUE_MENU,
    MATCH_MENU,
    WRITE_MENU,
    EXIT_MENU
} MENU;

typedef enum _VALUE_TYPE
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
    LPCVOID *addr;
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

void print_matches(MEMBLOCK *mb_list, VALUE_TYPE valueType);

int getDataSize(VALUE_TYPE valueType);

double read(HANDLE hProc, VALUE_TYPE valueType, LPCVOID addr);

void write(HANDLE hProc, VALUE_TYPE valueType, LPVOID addr, double val);

MEMBLOCK* createMemblock (HANDLE hProc, MEMORY_BASIC_INFORMATION *meminfo);

void freeMemblock (MEMBLOCK *mb);

void updateMemblock(MEMBLOCK *mb, SEARCH_CONDITION condition, double val, VALUE_TYPE valueType);

/**
 * Will return a mb pointer
 * which is the first element of the
 * linked list which represents the entire
 * memory contents of a process
*/
MEMBLOCK* createScan(unsigned int pid);

void freeScan (MEMBLOCK* mb_list);

/**
 * will the entire memblock
*/
void updateScan(MEMBLOCK* mb_list, SEARCH_CONDITION condition, double val, VALUE_TYPE valueType);

int getMatchesCount(MEMBLOCK *mb_list);

void enterPid(MEMBLOCK **scan, DWORD *pid);