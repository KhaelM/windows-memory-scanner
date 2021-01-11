#pragma once

#include "scanner.h"
#include "utils.h"

#define MAX_CHAR 15

void showValueTypeMenu(char *userInput, char *searchType, VALUE_TYPE *valueType);

void showMatchMenu(MEMBLOCK **scan, char *userInput, VALUE_TYPE *valueType, double *val, SEARCH_CONDITION *cond, DWORD *pid, MENU *uiMenu);

void showWriteMenu(double *val, MEMBLOCK *scan, LPVOID addrToWrite, char *userInput, char *searchType, VALUE_TYPE *valueType, MENU *uiMenu);

void showSearchValueMenu(char *userInput, char *searchType, VALUE_TYPE *valueType, MENU *uiMenu, SEARCH_CONDITION *cond, double *val, MEMBLOCK* scan);

void showMainMenu(MEMBLOCK *scan, DWORD *pid, char *userInput, MENU *uiMenu);