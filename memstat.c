#define _GNU_SOURCE        
#include <stdio.h>             
#include <stdlib.h>            
#include <dlfcn.h>
#include <sys/mman.h>  
#include <execinfo.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <bfd.h>

#include "memstat.h"

#define OUTOUT_BUFF_LEN 1024

static char tmpbuff[4096];
static unsigned long tmppos = 0;
static unsigned long tmpallocs = 0;

static int initializing = 0;

static u32 g_memstat_init = 0;
static u32 g_memstat_end = 0;

static struct MallocList g_stMallocList;

static void* (*g_malloc_func)(size_t) = NULL;
static void* (*g_realloc_func)(void *, size_t) = NULL;
static void (*g_free_func)(void *) = NULL;

int (*g_printf_func)(const s8 *fmt, ...);

static asymbol **syms;      /* Symbol table.  */

static bfd_vma pc;
static const char *filename;
static const char *functionname;
static unsigned int line;
static int found;

static void memstat_init();

static inline void print_trace()
{
    void *array[10];
    size_t size;
    s8 **strings;
    size_t i;
    pid_t pid = getpid();

    size = backtrace(array, 10);
    strings = backtrace_symbols(array, size);

    for(i = 0; i < size; i++) {
        printf("%s\n", strings[i]);
    }

    free(strings);
}

static int insert_stat_list(MEMSTAT_HEADER_S *pstMh)
{
    MEMSTAT_HEADER_S *pstEntry;
    
    list_for_each_entry(pstEntry, &g_stMallocList.stList, stList) {
        if (pstEntry->pallocd_by[0] == pstMh->pallocd_by[0] \
            && pstEntry->pallocd_by[1] == pstMh->pallocd_by[1] \
            && pstEntry->pallocd_by[2] == pstMh->pallocd_by[2]) {
            list_add(&pstMh->stList, &pstEntry->stHead);
            g_stMallocList.uCount++;
            return 0;
        }
    }

    list_add(&pstMh->stList, &g_stMallocList.stList);
    g_stMallocList.uCount++;

    return 0;
}

static int delete_from_stat_list(MEMSTAT_HEADER_S *pstMh)
{
    MEMSTAT_HEADER_S *pstEntry, *tmp;
    MEMSTAT_HEADER_S *pstFirst;
    
    if (list_empty(&pstMh->stHead)) {
        list_del(&pstMh->stList);
        g_stMallocList.uCount--;
        return 0;
    }

    pstFirst = list_first_entry(&pstMh->stHead, MEMSTAT_HEADER_S, stList);

    list_del(&pstFirst->stList);
    list_replace(&pstMh->stList, &pstFirst->stList);
    
    list_for_each_entry_safe(pstEntry, tmp, &pstMh->stHead, stList) {
        list_del(&pstEntry->stList);
        list_add(&pstEntry->stList, &pstFirst->stHead);
    }
 
    g_stMallocList.uCount--;

    return 0;
}


static void MagicValid(MEMSTAT_HEADER_S *pstMh, u64 u64Size)
{    
    int i;
    int stackSize;
    MEMSTAT_TAIL_S *pstTail;

    memset(pstMh, 0, sizeof(MEMSTAT_HEADER_S));

    pstMh->uMagicHead = MALLOC_MAGIC_HEAD;
    pstMh->uMemLen = u64Size;     
    INIT_LIST_HEAD(&pstMh->stHead);

    pstMh->pallocd_by[0] = __builtin_return_address(1);
    
    pstTail = (MEMSTAT_TAIL_S *)((uptr_t)pstMh + sizeof(MEMSTAT_HEADER_S) + u64Size);
    pstTail->uMagicTail = MALLOC_MAGIC_TAIL;

    pthread_mutex_lock(&g_stMallocList.stLock);
    insert_stat_list(pstMh);
    pthread_mutex_unlock(&g_stMallocList.stLock);

    return;
}

static void MagicInValid(MEMSTAT_HEADER_S *pstMh, s8 *uMem)
{
    MEMSTAT_TAIL_S *pstTail;
    
    pstTail = (MEMSTAT_TAIL_S *)((uptr_t)uMem + pstMh->uMemLen);
    
    pthread_mutex_lock(&g_stMallocList.stLock);
    delete_from_stat_list(pstMh);
    pthread_mutex_unlock(&g_stMallocList.stLock);
    
    pstMh->uMagicHead = FREE_MAGIC_HEAD;
    
    pstMh->pfreed_by[0] = __builtin_return_address(1);
   
    pstTail->uMagicTail = FREE_MAGIC_TAIL;

    return;
}

static void DumpMemory(u8 *beg, u8*end)
{
    u8 *ptr, *p;
	s32 i, len;

    if (NULL == g_printf_func) {
        g_printf_func = printf;
    }
    
	if (end <= beg) {
        return;
	}

	for (ptr = (u8 *)((uptr_t)beg & ~15); ptr <= end; ptr += 16) {
	    (*g_printf_func)("%8.8lx: ", (uptr_t)ptr);
		for (i = 0; i < 16; i ++) {
		    p = (ptr + i);
			if ((p < beg) || (p > end)) {
			     (*g_printf_func)("   ");
			} else {
			    (*g_printf_func)("%2.2lx ", (u32)*p);
			}
		}

		(*g_printf_func)(" |  ");
		len = end - ptr;
		if (len > 15) {
            len = 15;
		}

		for (i = 0; i <= len; i ++) {
		    p = ptr + i;
			if (p < beg) {
			    (*g_printf_func)(" ");
			} else {
			    (*g_printf_func)("%c", ((*p > 31) && (*p < 128)) ? *p:'.');
			}
		}

        (*g_printf_func)("\n");
	}        
}


static void MallocDumpMe(u8 *ucAddr)
{
    u8 *ucEnd = (u8 *)((uptr_t)ucAddr + 0x2ff);
    
    DumpMemory(ucAddr,ucEnd);
}

static int MemCheck(u8 *u8Mem)
{
    MEMSTAT_TAIL_S *pstTail;
    MEMSTAT_HEADER_S *pstMh = (MEMSTAT_HEADER_S *)((size_t)u8Mem - sizeof(MEMSTAT_HEADER_S));        
  
    if (MALLOC_MAGIC_HEAD != pstMh->uMagicHead) {	     
        //MallocDumpMe((u8 *)pstMh);
        return -1;
    }
    
    pstTail = (MEMSTAT_TAIL_S *)(u8Mem + pstMh->uMemLen);
    if (MALLOC_MAGIC_TAIL != pstTail->uMagicTail) {
        //MallocDumpMe((u8 *)pstMh);
        return -1;
    }
    
    return 0;
}

static int slurp_symtab(bfd * abfd)
{
	long symcount;
	unsigned int size;

	if ((bfd_get_file_flags(abfd) & HAS_SYMS) == 0) {
		return -1;
	}

	symcount = bfd_read_minisymbols(abfd, false, (PTR) & syms, &size);
	if (symcount == 0) {
		symcount = bfd_read_minisymbols(abfd, true, (PTR) & syms, &size);
	}

	if (symcount < 0) {
        return -1;
	}

    return 0;
}

static void find_addr_sect(bfd *abfd, asection *section, void *obj)
{
    bfd_data *data = (bfd_data *)obj;
    bfd_vma vma;
    bfd_size_type size;
    const char *filename = NULL;
    const char *function = NULL;

    if (data->found) {
        return;
    }

    if (!(bfd_section_vma(abfd, section)))
        return;

    vma = bfd_section_vma(abfd, section);
    if (data->pc < vma) {
        return;
    }

    size = bfd_section_size(abfd, section);
    if (data->pc >= vma + size) {
        return;
    }

    data->found = bfd_find_nearest_line(abfd, section, syms,
                        data->pc - vma,
                        &filename,
                        &function,
                        &data->line);
    
    if (data->found && filename != NULL && function != NULL) {
        strncpy(data->filename, filename, MAX_BUFF_LEN - 1);
        strncpy(data->function, function, MAX_BUFF_LEN - 1);
    }

    return;
}

static int find_symbol(bfd_data *data)
{
	Dl_info info;
    bfd *abfd = NULL;
	char **matching;

	dladdr((void *)data->pc, &info);

	abfd = bfd_openr(info.dli_fname, NULL);

	if (abfd == NULL) {
		return -1;
	}

    strcpy(data->dli_fname, info.dli_fname);

	if (bfd_check_format(abfd, bfd_archive)) {
        goto ERROR;
	}

	if (!bfd_check_format_matches(abfd, bfd_object, &matching)) {
		if (bfd_get_error() == bfd_error_file_ambiguously_recognized) {
			free(matching);
		}
		goto ERROR;
	}

	slurp_symtab(abfd);

	bfd_map_over_sections(abfd, find_addr_sect, data);

	if (syms != NULL) {
		free(syms);
		syms = NULL;
	}

	bfd_close(abfd);

    return 0;
ERROR:
    if (abfd != NULL) {
		bfd_close(abfd);
	}
    
    return -1;
}

int addr_to_function(void *addr, char *buff, u32 buff_len)
{
    bfd_data data;

    memset(&data, 0, sizeof(data));

    data.pc = (bfd_vma)addr;
    data.found = false;
    
    find_symbol(&data);
    
    if (data.found == true) {
        memset(buff, 0, sizeof(buff_len));
        strncpy(buff, data.function, buff_len); 
        return 0; 
    }

    return -1;
}

static int insert_list_desc(MEMSTAT_HEADER_S *pstNew, LIST_HEAD_S *pstDup)
{
    MEMSTAT_HEADER_S *pstEntry;
    MEMSTAT_HEADER_S *pstTmp;

    list_for_each_entry_safe(pstEntry, pstTmp, pstDup, stList) {
        if (pstEntry->uTotalCount < pstNew->uTotalCount) {
            list_add_tail(&pstNew->stList, &pstEntry->stList); 
            return 0;
        }   
    }

    list_add_tail(&pstNew->stList, pstDup);

    return 0;
}

static int dup_list(LIST_HEAD_S *pstOrigin, LIST_HEAD_S *pstDup)
{
    MEMSTAT_HEADER_S *pstEntry;
    MEMSTAT_HEADER_S *pstEntry1;
    MEMSTAT_HEADER_S *pstNew;
    MEMSTAT_HEADER_S *pstNew1;

    u32 uTotalCount;
    u32 uTotalLen;
    
    INIT_LIST_HEAD(pstDup);

    list_for_each_entry(pstEntry, pstOrigin, stList) {
        pstNew = (MEMSTAT_HEADER_S *)g_malloc_func(sizeof(MEMSTAT_HEADER_S));
        if (pstNew == NULL) {
            goto ERROR;
        }
        *pstNew = *pstEntry;
        INIT_LIST_HEAD(&pstNew->stHead);

        uTotalCount = 1;
        uTotalLen = pstEntry->uMemLen;
        
        list_for_each_entry(pstEntry1, &pstEntry->stHead, stList) {
            uTotalLen += pstEntry1->uMemLen;
            uTotalCount++;
        }
        
        pstNew->uTotalLen = uTotalLen;
        pstNew->uTotalCount = uTotalCount;

        insert_list_desc(pstNew, pstDup);
    }

    return 0;
ERROR:
    return -1;
}

static int free_list(LIST_HEAD_S *pstDup)
{
    MEMSTAT_HEADER_S *pstEntry;
    MEMSTAT_HEADER_S *pstTmp;
    MEMSTAT_HEADER_S *pstEntry1;
    MEMSTAT_HEADER_S *pstTmp1;

    list_for_each_entry_safe(pstEntry, pstTmp, pstDup, stList) {
        list_del(&pstEntry->stList);

        list_for_each_entry_safe(pstEntry1, pstTmp1, &pstEntry->stHead, stList) {
            list_del(&pstEntry1->stList);
            g_free_func(pstEntry1);
        }

        g_free_func(pstEntry);
    }

    return 0;
}

int CollectMemStat(char *pcOutFile)
{
    LIST_HEAD_S dup_head;
    MEMSTAT_HEADER_S *pstEntry;
    MEMSTAT_HEADER_S *pstEntry1;
    bfd_vma addr;
    bfd_data data;
    bfd_data data1;
    u32 uTotalCount;
    u32 uTotalLen;
    FILE *fp;
    char buff[OUTOUT_BUFF_LEN];
    u32 u32OutLen = 0;
    time_t ts;

    pthread_mutex_lock(&g_stMallocList.stLock);
    dup_list(&g_stMallocList.stList, &dup_head);
    pthread_mutex_unlock(&g_stMallocList.stLock);

    time(&ts);

    fp = fopen(pcOutFile, "a");
    if (fp == NULL) {
        return -1;
    }

    memset(buff, 0, OUTOUT_BUFF_LEN);
    u32OutLen += sprintf(buff + u32OutLen, "\nTime:%s", ctime(&ts));

    fwrite(buff, 1, strlen(buff), fp);

    list_for_each_entry(pstEntry, &dup_head, stList) {
        memset(buff, 0, OUTOUT_BUFF_LEN);
        u32OutLen = 0;
        uTotalCount = pstEntry->uTotalCount;
        uTotalLen = pstEntry->uTotalLen;

        memset(&data, 0, sizeof(data));
	    data.pc = (bfd_vma)pstEntry->pallocd_by[0];
	    data.found = false;
        find_symbol(&data);

        u32OutLen = sprintf(buff, "Count:%10d  TotalLen:%12d  ", uTotalCount, uTotalLen);  
        if (data.found > 0 && data.filename != NULL && data.function != NULL) {
            u32OutLen += sprintf(buff + u32OutLen, "Addr_0:%p\tdl:%s\tLine_0:%s:%d\tFunction_0:%s", data.pc, data.dli_fname, data.filename, data.line, data.function);
        } else {
            u32OutLen += sprintf(buff + u32OutLen, "Addr_0:%p\tdl:%s\tLine_0:unknown:0\tFunction_0:unknown", data.pc, data.dli_fname);
        }

        if (pstEntry->pallocd_by[1] != 0) {
            memset(&data1, 0, sizeof(data1));
    	    data1.pc = (bfd_vma)pstEntry->pallocd_by[1];
    	    data1.found = false;
            find_symbol(&data1);
            if (data1.found > 0 && data1.filename != NULL && data1.function != NULL) {
                u32OutLen += sprintf(buff + u32OutLen, "Addr_1:%p\tdl:%s\tLine_1:%s:%d\tFunction_1:%s", data1.pc, data1.dli_fname, data1.filename, data1.line, data1.function);
            } else {
                u32OutLen += sprintf(buff + u32OutLen, "Addr_0:%p\tdl:%s\tLine_0:unknown:0\tFunction_0:unknown", data1.pc, data1.dli_fname);
            }
        }

        buff[u32OutLen] = '\n';

        fwrite(buff, 1, strlen(buff), fp);
    }

    free_list(&dup_head);

    fflush(fp);
    fclose(fp);

    return 0;
}

void *malloc(size_t u64Size)
{
    s8 *pcBlock = NULL;
    u64 u64MemSize;
    MEMSTAT_HEADER_S *pstMh;

    if (g_memstat_init == 0) {
        if (initializing == 1) {
           if (tmppos + u64Size < sizeof(tmpbuff)) {
                void *retptr = tmpbuff + tmppos;
                tmppos += u64Size;
                ++tmpallocs;
                return retptr;
            } else {
                fprintf(stdout, "too much memory requested during initialisation - increase tmpbuff size\n");
                exit(1);
            } 
        } else {
            memstat_init();
            g_memstat_init = 1;
        }
    }

    u64MemSize = u64Size + sizeof(MEMSTAT_HEADER_S) + sizeof(MEMSTAT_TAIL_S);

    pstMh = g_malloc_func(u64MemSize);
    
    if (pstMh != NULL) {
        MagicValid(pstMh, u64Size);
        pcBlock = (s8 *)((uptr_t)pstMh + sizeof(MEMSTAT_HEADER_S));
        
        return pcBlock;
    }
    
    return NULL;
}

void* realloc(void *pOldMemPtr, size_t u64NewSize)
{
    s8 *pcBlock = NULL;
    MEMSTAT_HEADER_S *pstMh;
    MEMSTAT_HEADER_S *pstNewMh;
    size_t u64MemSize;

    if (g_memstat_init == 0) {
        memstat_init();
        g_memstat_init = 1;
    }
    
    if (NULL == pOldMemPtr) {
        return malloc(u64NewSize);
    }

    u64MemSize = u64NewSize + sizeof(MEMSTAT_HEADER_S) + sizeof(MEMSTAT_TAIL_S);   
    pstMh = (MEMSTAT_HEADER_S *)((uptr_t)pOldMemPtr - sizeof(MEMSTAT_HEADER_S));
    
    if (-1 == MemCheck(pOldMemPtr)) {
        return NULL;
    }
    
    MagicInValid(pstMh, pOldMemPtr);
    
    pstNewMh = g_realloc_func(pstMh, u64MemSize);
    
    if( pstNewMh != NULL ) {
        MagicValid(pstNewMh, u64NewSize);
        pcBlock = (s8 *)((uptr_t)pstNewMh + sizeof(MEMSTAT_HEADER_S));
        return pcBlock;
    }
    
    return NULL;
}

void *calloc(size_t nmemb, size_t size)
{  
    void *ptr = NULL;
    size_t u64Size = nmemb * size;
    s8 *pcBlock = NULL;
    u64 u64MemSize;
    MEMSTAT_HEADER_S *pstMh;

    if (g_memstat_init == 0) {
        if (initializing == 1) {
           if (tmppos + u64Size < sizeof(tmpbuff)) {
                void *retptr = tmpbuff + tmppos;
                tmppos += u64Size;
                ++tmpallocs;
                return retptr;
            } else {
                fprintf(stdout, "too much memory requested during initialisation - increase tmpbuff size\n");
                exit(1);
            } 
        } else {
            memstat_init();
            g_memstat_init = 1;
        }
    }

    u64MemSize = u64Size + sizeof(MEMSTAT_HEADER_S) + sizeof(MEMSTAT_TAIL_S);

    pstMh = g_malloc_func(u64MemSize);
    if (pstMh != NULL) {
        MagicValid(pstMh, u64Size);
        pcBlock = (s8 *)((uptr_t)pstMh + sizeof(MEMSTAT_HEADER_S));
	    memset(pcBlock, 0, u64Size);
        return pcBlock;
    }
    
    return NULL;
}

void free(void *ppBuf)
{
    MEMSTAT_HEADER_S *pstMh;
    
    if (ppBuf == NULL) {
	    return;
    }

    /* freeing temp memory */
    if (ppBuf >= (void*) tmpbuff && ppBuf <= (void*)(tmpbuff + tmppos)) {
        ;   
    }
   
    pstMh = (MEMSTAT_HEADER_S *)((uptr_t)ppBuf - sizeof(MEMSTAT_HEADER_S));
    
    if (-1 == MemCheck(ppBuf)) {
        return;
    }
    
    MagicInValid(pstMh, (s8 *)ppBuf);
    
    g_free_func(pstMh);
    
    return;
}

static void memstat_init()
{
    initializing = 1;

    memset(&g_stMallocList, 0, sizeof(g_stMallocList));
    
    INIT_LIST_HEAD(&g_stMallocList.stList);

    pthread_mutex_init(&g_stMallocList.stLock, NULL);
    
    g_malloc_func = dlsym(RTLD_NEXT, "malloc");
    if (!g_malloc_func) {   
        initializing = 0;
        exit(1);
    }
    
    g_free_func = dlsym(RTLD_NEXT, "free");
    if (!g_free_func) {   
        initializing = 0;
        exit(1);
    }

    g_realloc_func = dlsym(RTLD_NEXT, "realloc");
    if (!g_free_func) {   
        initializing = 0;
        exit(1);
    }

    initializing = 0;

    return;
}
