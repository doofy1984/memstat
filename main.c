#include <stdio.h>             
#include <stdlib.h>            
#include <string.h>
#include <unistd.h>

#define MALLOC_NUM 1024

int CollectMemStat(char *pcOutFile);

int main()
{
    int i;
    void *p;
    void *arrPtr[MALLOC_NUM];

    for(i = 0; i < MALLOC_NUM; i++) {
        arrPtr[i] = malloc(i);
    }

    for(i = 0; i < MALLOC_NUM; i++) {
        if (i != MALLOC_NUM/2 && i != MALLOC_NUM/4) {
            free(arrPtr[i]);
        }
    }

    for (i = 0; i < 5; i++) {
        malloc(300);
    }

    for (i = 0; i < 2; i++) {
        malloc(1300);
    }

    CollectMemStat("./memstat.data");

    return 0;
}
