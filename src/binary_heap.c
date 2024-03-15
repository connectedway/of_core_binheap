/* Copyright (c) 2021 Connected Way, LLC. All rights reserved.
 * Use of this source code is governed by a Creative Commons 
 * Attribution-NoDerivatives 4.0 International license that can be
 * found in the LICENSE file.
 */
#if defined(_WINCE_)
#include <windows.h>
#endif
#if defined(__ANDROID__) || defined(ANDROID) || defined(__linux__) || defined(__APPLE__)

#include <sys/mman.h>

#endif

#include "ofc/config.h"
#include "ofc/types.h"
#include "ofc/libc.h"
#include "ofc/lock.h"
#include "ofc/console.h"
#include "ofc/process.h"

#include "ofc/heap.h"
#include "ofc/impl/heapimpl.h"

#include "ofh/config.h"

#define POWER_LOW 0
#define OFC_HEAP_FENCE 0x52

struct binheap_chunk {
    union {
        OFC_INT power;
        struct binheap_chunk *next;
    } u;
#if defined(OFC_HEAP_DEBUG)
    OFC_BOOL crumb;
    OFC_SIZET alloc_size;
#endif
};

static OFC_VOID binheap_power_free(OFC_INT power,
                                   struct binheap_chunk *chunk);

static struct binheap_chunk *binheap_power_alloc(OFC_INT power,
                                                 OFC_SIZET alloc_size);

static OFC_INT binheap_power_find(OFC_SIZET size);

#if defined(_WINCE_) || defined(__ANDROID__) || defined(ANDROID) || defined(__linux__) || defined(__APPLE__)
static OFC_UINT32 *heap;
#else
static OFC_UINT32 heap[1 << (OFC_HEAP_POWER-2) ] ;
#endif

static struct binheap_chunk *binheap[OFC_HEAP_POWER + 1];
static OFC_LOCK binheap_lock;

static OFC_INT binheap_power_find(OFC_SIZET size) {
    OFC_INT i;

    for (i = 0; size > 0; size = size >> 1, i++);

    return (i);
}

OFC_VOID binheap_check_alloc(const struct binheap_chunk *chunk) {
#if defined(OFC_HEAP_DEBUG)
    OFC_CCHAR *unused;

    if (!chunk->crumb) {
        ofc_process_crash("Something Allocated without a crumb\n");
    }
    /*
     * Let's check that it hasn't done a buffer overrun
     */
    for (unused = (OFC_CCHAR *) (chunk + 1) + chunk->alloc_size;
         unused < (OFC_CCHAR *) (chunk) + (1 << chunk->u.power);
         unused++)
        if (*unused != OFC_HEAP_FENCE)
            ofc_process_crash("Fence Intrusion Detected\n");
#endif
}

static OFC_VOID binheap_power_free(OFC_INT power,
                                   struct binheap_chunk *chunk) {
#if defined(OFC_HEAP_POISON)
    OFC_UINT32 *pmem;
    OFC_INT i;
    OFC_INT bound;
#endif

    ofc_lock(binheap_lock);
#if defined(OFC_HEAP_DEBUG)
    binheap_check_alloc(chunk);
    chunk->crumb = OFC_FALSE;
#endif
#if defined(OFC_HEAP_POISON)
    pmem = (OFC_UINT32 *) (chunk + 1);
    bound = (2 ^ power) - sizeof(chunk);
    for (i = 0; i < bound; i += sizeof(OFC_UINT32))
        *pmem++ = 0xFFFFFFFF;
#endif

    chunk->u.next = binheap[power];
    binheap[power] = chunk;
    ofc_unlock(binheap_lock);
}

#if 0
#if defined(__ANDROID__) || defined(ANDROID)
#include <stdlib.h>
#include <errno.h>

static OFC_VOID print_library_address(OFC_CCHAR *library_name) 
{ 
  FILE* file ;
  OFC_UINT addr = 0; 
  OFC_INT len_libname ;
  OFC_CHAR buff[256]; 

  len_libname = ofc_strlen(library_name); 

  file = fopen ("/proc/self/maps", "rt"); 

  if (file != OFC_NULL) 
    {
      while (fgets(buff, sizeof buff, file) != NULL)
	{ 
	  // dump entire file (all lines)
	  // but also search for libandroidsmb
	  ofc_write_console(buff);
	  OFC_INT len = ofc_strlen(buff); 

	  if (len > 0 && buff[len-1] == '\n') 
	    { 
	      buff[--len] = '\0'; 
	    } 

	  if (len > len_libname &&
	      ofc_memcmp(buff + len - len_libname,
			 library_name, len_libname) == 0)
	    {
	      size_t start ;
	      size_t end ;
	      size_t offset; 
	      OFC_CHAR flags[4]; 

	      if (sscanf (buff, "%zx-%zx %c%c%c%c %zx", &start, &end, 
			  &flags[0], &flags[1], &flags[2], &flags[3], 
			  &offset ) == 7) 
		{
		  if (flags[0]=='r' && flags[1]=='-' && flags[2]=='x') 
		    { 
		      addr = (OFC_UINT) (start - offset); 
		    } 
		}
	    }
	} 
    }

  fclose (file); 

  ofc_snprintf(buff, 256, "%s loaded at 0x%08x\n",
	       library_name, addr);
  ofc_write_console(buff);
} 
#endif
#endif

static struct binheap_chunk *binheap_power_alloc(OFC_INT power,
                                                 OFC_SIZET alloc_size) {
    struct binheap_chunk *chunk;
    struct binheap_chunk *next_chunk;
#if defined(OFC_HEAP_POISON)
    OFC_UINT32 *pmem;
    OFC_INT i;
    OFC_INT bound;
#endif
#if defined(OFC_HEAP_DEBUG)
    OFC_CHAR *unused;
#endif

    if (power < POWER_LOW)
        power = POWER_LOW;
    if (power < OFC_HEAP_POWER + 1) {
        ofc_lock(binheap_lock);
        if (binheap[power] != OFC_NULL) {
            chunk = binheap[power];
            binheap[power] = chunk->u.next;
            ofc_unlock(binheap_lock);
#if defined(OFC_HEAP_DEBUG)
            if (chunk->crumb) {
                ofc_process_crash("Allocated something with a crumb\n");
            }
            chunk->crumb = OFC_TRUE;
            chunk->alloc_size = alloc_size;

            /*
             * Let's Make a Fence
             */
            for (unused = (OFC_CHAR *) (chunk + 1) + chunk->alloc_size;
                 unused < (OFC_CHAR *) (chunk) + (1 << power);
                 unused++)
                *unused = OFC_HEAP_FENCE;
#endif
            chunk->u.power = power;
        } else {
            ofc_unlock(binheap_lock);
            chunk = binheap_power_alloc(power + 1, alloc_size);
            if (chunk != OFC_NULL) {
                next_chunk = (struct binheap_chunk *)
                        ((OFC_CHAR *) chunk + (1 << power));
                chunk->u.power = power;
                next_chunk->u.power = power;
#if defined(OFC_HEAP_DEBUG)
                next_chunk->crumb = OFC_TRUE;
                next_chunk->alloc_size =
                        (1 << power) - sizeof(struct binheap_chunk);
#endif
                binheap_power_free(power, next_chunk);
            }

        }
#if defined(OFC_HEAP_POISON)
        pmem = (OFC_UINT32 *) (chunk + 1);
        bound = (2 ^ power) - sizeof(chunk);
        for (i = 0; i < bound; i += sizeof(OFC_UINT32))
            *pmem++ = 0xFFFFFFFF;
#endif
    } else {
        chunk = OFC_NULL;
#if 0
	print_library_address("libof_smb_jni.so");
	print_library_address("libof_core_jni.so");
#endif
        ofc_heap_dump();
        ofc_process_crash("Heap Exhausted\n");
    }
    return (chunk);
}

#if defined(OFC_HEAP_CHECK) && defined(OFC_HEAP_DEBUG)

OFC_VOID binheap_debug_check(OFC_VOID) {
    struct binheap_chunk *chunk;
    OFC_INT i;
    /*
     * All crumbs should be false
     */
    ofc_lock(binheap_lock);

    for (i = 0; i < OFC_HEAP_POWER + 1; i++) {
        for (chunk = binheap[i]; chunk != OFC_NULL; chunk = chunk->u.next) {
            if (chunk->crumb) {
                ofc_process_crash("Found a crumb in binary heap\n");
            } else
                chunk->crumb = OFC_TRUE;
        }
    }
    /*
     * Reset the crumbs
     */
    for (i = 0; i < OFC_HEAP_POWER + 1; i++) {
        for (chunk = binheap[i]; chunk != OFC_NULL; chunk = chunk->u.next) {
            if (!chunk->crumb) {
                ofc_process_crash("Found a crumb\n");
            } else
                chunk->crumb = OFC_FALSE;
        }
    }

    ofc_unlock(binheap_lock);
}

#endif

OFC_VOID ofc_heap_init_impl(OFC_VOID) {
    struct binheap_chunk *chunk;
    OFC_INT i;
#if defined(_WINCE_)
    DWORD size ;
#endif
#if defined(__ANDROID__) || defined(ANDROID) || defined(__linux__) || defined(__APPLE__)
    size_t size;
#endif

    for (i = 0; i < OFC_HEAP_POWER + 1; i++) {
        binheap[i] = OFC_NULL;
    }

#if defined(_WINCE_)
    size = (1 << OFC_HEAP_POWER) ;

    heap = (OFC_UINT32 *) VirtualAlloc (0, size, MEM_RESERVE, PAGE_NOACCESS);
    heap = (OFC_UINT32 *) VirtualAlloc (heap, size, MEM_COMMIT, PAGE_READWRITE);
    chunk = (OFC_VOID *) heap ;
#elif defined(__ANDROID__) || defined(ANDROID) || defined(__linux__) || defined(__APPLE__)
    size = (1 << OFC_HEAP_POWER);

    heap = (OFC_UINT32 *) mmap(NULL, size, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS,
                               -1, 0);
    chunk = (OFC_VOID *) heap;
#else
    chunk = (OFC_VOID *) heap ;
#endif

#if defined(OFC_HEAP_DEBUG)
    chunk->crumb = OFC_TRUE;
    chunk->alloc_size =
            (1 << OFC_HEAP_POWER) - sizeof(struct binheap_chunk);
#endif
    binheap_power_free(OFC_HEAP_POWER, chunk);
    binheap_lock = ofc_lock_init();
}

OFC_VOID ofc_heap_unload_impl(OFC_VOID)
{
  OFC_LOCK save;

  save = binheap_lock;
  binheap_lock = OFC_NULL;
  ofc_lock_destroy(save);
}

OFC_VOID ofc_heap_unmap_impl(OFC_VOID)
{
#if defined(_WINCE_)
  DWORD size ;
  size = (1 << OFC_HEAP_POWER) ;

  VirtualFree (heap, size, MEM_DECOMMIT);
  VirtualFree (0, size, MEM_RELEASE);
  heap = NULL ;
#elif defined(__ANDROID__) || defined(ANDROID) || defined(__linux__) || defined(__APPLE__)
  size_t size;

  size = (1 << OFC_HEAP_POWER);

  munmap(heap, size);
  heap = NULL;
#endif
}

OFC_LPVOID ofc_malloc_impl(OFC_SIZET size) {
    OFC_INT power;
    struct binheap_chunk *chunk;
    OFC_LPVOID mem;

    if (size > 100000)
        ofc_process_crash("Allocating something huge\n");

    power = binheap_power_find(size + sizeof(struct binheap_chunk));
    chunk = binheap_power_alloc(power, size);

    mem = (OFC_LPVOID) (++chunk);

#if defined(OFC_HEAP_CHECK) && defined(OFC_HEAP_DEBUG)
    binheap_debug_check();
#endif
    return (mem);
}

OFC_VOID ofc_heap_check_alloc_impl(OFC_LPCVOID mem) {
#if defined(OFC_HEAP_DEBUG)
    const struct binheap_chunk *chunk;

    if (mem != OFC_NULL) {
        chunk = mem;
        chunk--;

        binheap_check_alloc(chunk);
    }
#endif
}

OFC_VOID ofc_free_impl(OFC_LPVOID mem) {
    struct binheap_chunk *chunk;

    if (mem != OFC_NULL) {
        chunk = mem;
        chunk--;

        binheap_power_free(chunk->u.power, chunk);
#if defined(OFC_HEAP_CHECK) && defined(OFC_HEAP_DEBUG)
        binheap_debug_check();
#endif
    }
}

OFC_LPVOID ofc_realloc_impl(OFC_LPVOID ptr, OFC_SIZET size) {
    struct binheap_chunk *chunk;
    struct binheap_chunk *newchunk;
    OFC_INT power;

#if defined(OFC_HEAP_CHECK) && defined(OFC_HEAP_DEBUG)
    binheap_debug_check();
#endif

    chunk = ptr;
    power = binheap_power_find(size + sizeof(struct binheap_chunk));

    if (chunk != OFC_NULL) {
        chunk--;
        if (power > chunk->u.power) {
            newchunk = binheap_power_alloc(power, size);
            ofc_memcpy(newchunk + 1, chunk + 1,
                       (1 << chunk->u.power) - sizeof(struct binheap_chunk));

            binheap_power_free(chunk->u.power, chunk);
            chunk = newchunk;
        }
#if defined(OFC_HEAP_DEBUG)
        else {
            OFC_CHAR *unused;
            chunk->alloc_size = size;
            /*
             * Let's Make a Fence
             */
            for (unused = (OFC_CHAR *) (chunk + 1) + chunk->alloc_size;
                 unused < (OFC_CHAR *) (chunk) + (1 << chunk->u.power);
                 unused++)
                *unused = OFC_HEAP_FENCE;
        }
#endif
    } else {
        chunk = binheap_power_alloc(power, size);
    }

    chunk++;
#if defined(OFC_HEAP_CHECK) && defined(OFC_HEAP_DEBUG)
    binheap_debug_check();
#endif
    return (chunk);
}

