#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <pthread.h>

#include "types.h"
#include "list.h"

#define MAX_BUFF_LEN    256

typedef struct
{
    LIST_HEAD_S stList;
    u32     uMagicHead;
    u32     uMemLen;
	void    *pallocd_by[3];
	void    *pfreed_by[3];
    time_t  *tv;
    LIST_HEAD_S stHead;     // same ptr pallocd_by[3]
    u32     uTotalLen;
    u32     uTotalCount;         // count of nodes in  stHead
} MEMSTAT_HEADER_S;

typedef struct
{
    u32 uMagicTail;
} MEMSTAT_TAIL_S;

struct MallocList {
	u32 uCount;
    LIST_HEAD_S stList;
    pthread_mutex_t stLock;
};

typedef struct
{
    const s8 *addr;
    size_t  size;
    u32     malloc_count;
    u32     line;
    LIST_HEAD_S stList;
} MEMSTAT_INFO_S;

typedef struct 
{
    bfd_vma pc;
    char dli_fname[MAX_BUFF_LEN];
    char filename[MAX_BUFF_LEN];
    char function[MAX_BUFF_LEN];
    unsigned int line;
    int found;
} bfd_data;


#define MALLOC_MAGIC_HEAD_ONE   ((u8)0xa5)
#define MALLOC_MAGIC_TAIL_ONE   ((u8)0x3c)

#define MALLOC_MAGIC_HEAD       ((u32)0xa5a5a5a5)
#define MALLOC_MAGIC_TAIL       ((u32)0x3c3c3c3c)

#define FREE_MAGIC_HEAD         ((u32)0x1e1e1e1e)
#define FREE_MAGIC_TAIL         ((u32)0x78787878)

#endif
