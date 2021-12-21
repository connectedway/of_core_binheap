/* Copyright (c) 2009 Blue Peach Solutions, Inc.
 * All rights reserved.
 *
 * This software is protected by copyright and intellectual
 * property laws as well as international treaties.  It is to be
 * used and copied only by authorized licensees under the
 * conditions described in their licenses.
 *
 * Title to and ownership of the software shall at all times
 * remain with Blue Peach Solutions.
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
#define BLUE_HEAP_FENCE 0x52

struct binheap_chunk
{
  union
  {
    BLUE_INT power ;
    struct binheap_chunk * next ;
  } u ;
#if defined(BLUE_PARAM_HEAP_DEBUG)
  BLUE_BOOL crumb ;
  BLUE_SIZET alloc_size ;
#endif
} ;

static BLUE_VOID binheap_power_free (BLUE_INT power,
				     struct binheap_chunk * chunk) ;
static struct binheap_chunk * binheap_power_alloc (BLUE_INT power,
						   BLUE_SIZET alloc_size) ;
static BLUE_INT binheap_power_find (BLUE_SIZET size) ;

#if defined(_WINCE_) || defined(__ANDROID__) || defined(ANDROID) || defined(__linux__) || defined(__APPLE__)
static BLUE_UINT32 *heap ;
#else
static BLUE_UINT32 heap[1 << (BLUE_PARAM_HEAP_POWER-2) ] ;
#endif

static struct binheap_chunk * binheap[BLUE_PARAM_HEAP_POWER+1] ;
static BLUE_LOCK binheap_lock ;

static BLUE_INT binheap_power_find (BLUE_SIZET size)
{
  BLUE_INT i ;

  for (i = 0 ; size > 0 ; size = size >> 1, i++) ;

  return (i) ;
}

BLUE_VOID binheap_check_alloc (const struct binheap_chunk * chunk)
{
#if defined(BLUE_PARAM_HEAP_DEBUG)
  BLUE_CCHAR *unused ;

  if (!chunk->crumb)
    {
      BlueProcessCrash ("Something Allocated without a crumb\n") ;
    }
  /*
   * Let's check that it hasn't done a buffer overrun
   */
  for (unused = (BLUE_CCHAR *) (chunk+1) + chunk->alloc_size ;
       unused < (BLUE_CCHAR *) (chunk) + (1<<chunk->u.power) ;
       unused++)
    if (*unused != BLUE_HEAP_FENCE)
      BlueProcessCrash ("Fence Intrusion Detected\n") ;
#endif
}

static BLUE_VOID binheap_power_free (BLUE_INT power,
				     struct binheap_chunk * chunk)
{
#if defined(BLUE_PARAM_HEAP_POISON)
  BLUE_UINT32 *pmem ;
  BLUE_INT i ;
  BLUE_INT bound ;
#endif

  binheap_lock = BlueLockInit () ;
#if defined(BLUE_PARAM_HEAP_DEBUG)
  binheap_check_alloc (chunk) ;
  chunk->crumb = BLUE_FALSE ;
#endif
#if defined(BLUE_PARAM_HEAP_POISON)
  pmem = (BLUE_UINT32*) (chunk+1) ;
  bound = (2^power) - sizeof(chunk) ;
  for (i = 0 ; i < bound ; i+=sizeof(BLUE_UINT32))
    *pmem++ = 0xFFFFFFFF ;
#endif

  chunk->u.next = binheap[power] ;
  binheap[power] = chunk ;
  BlueUnlock (binheap_lock) ;
}

static struct binheap_chunk * binheap_power_alloc (BLUE_INT power, 
						   BLUE_SIZET alloc_size)
{
  struct binheap_chunk * chunk ;
  struct binheap_chunk * next_chunk ;
#if defined(BLUE_PARAM_HEAP_POISON)
  BLUE_UINT32 *pmem ;
  BLUE_INT i ;
  BLUE_INT bound ;
#endif
#if defined(BLUE_PARAM_HEAP_DEBUG)
  BLUE_CHAR *unused ;
#endif

  if (power < POWER_LOW)
    power = POWER_LOW ;
  if (power < BLUE_PARAM_HEAP_POWER+1)
    {
      BlueLock (binheap_lock) ;
      if (binheap[power] != BLUE_NULL)
	{
	  chunk = binheap[power] ;
	  binheap[power] = chunk->u.next ;
	  BlueUnlock (binheap_lock) ;
#if defined(BLUE_PARAM_HEAP_DEBUG)
	  if (chunk->crumb)
	    {
	      BlueProcessCrash ("Allocated something with a crumb\n") ;
	    }
	  chunk->crumb = BLUE_TRUE ;
	  chunk->alloc_size = alloc_size ;

	  /*
	   * Let's Make a Fence
	   */
	  for (unused = (BLUE_CHAR *) (chunk+1) + chunk->alloc_size ;
	       unused < (BLUE_CHAR *) (chunk) + (1<<power) ;
	       unused++)
	    *unused = BLUE_HEAP_FENCE ;
#endif
	  chunk->u.power = power ;
	}
      else
	{
	  BlueUnlock (binheap_lock) ;
	  chunk = binheap_power_alloc (power + 1, alloc_size) ;
	  if (chunk != BLUE_NULL)
	    {
	      next_chunk = (struct binheap_chunk *) 
		((BLUE_CHAR *)chunk + (1<<power)) ;
	      chunk->u.power = power ;
	      next_chunk->u.power = power ;
#if defined(BLUE_PARAM_HEAP_DEBUG)
	      next_chunk->crumb = BLUE_TRUE ;
	      next_chunk->alloc_size = 
		(1<<power) - sizeof (struct binheap_chunk) ;
#endif
	      binheap_power_free (power, next_chunk) ;
	    }
	  
	}
#if defined(BLUE_PARAM_HEAP_POISON)
      pmem = (BLUE_UINT32*) (chunk+1) ;
      bound = (2^power) - sizeof(chunk) ;
      for (i = 0 ; i < bound ; i+=sizeof(BLUE_UINT32))
	*pmem++ = 0xFFFFFFFF ;
#endif
    }
  else
    {
      chunk = BLUE_NULL ;
      BlueHeapDump() ;
      BlueProcessCrash ("Heap Exhausted\n") ;
    }
  return (chunk) ;
}

#if defined(BLUE_PARAM_HEAP_CHECK)
BLUE_VOID binheap_debug_check (BLUE_VOID)
{
  struct binheap_chunk *chunk ;
  BLUE_INT i ;
  /*
   * All crumbs should be false
   */
  BlueLock (binheap_lock) ;

  for (i = 0 ; i < BLUE_PARAM_HEAP_POWER + 1 ; i++)
    {
      for (chunk = binheap[i] ; chunk != BLUE_NULL; chunk = chunk->u.next)
	{
	  if (chunk->crumb)
	    {
	      BlueProcessCrash ("Found a crumb in binary heap\n") ;
	    }
	  else
	    chunk->crumb = BLUE_TRUE ;
	}
    }
  /*
   * Reset the crumbs
   */
  for (i = 0 ; i < BLUE_PARAM_HEAP_POWER + 1 ; i++)
    {
      for (chunk = binheap[i] ; chunk != BLUE_NULL; chunk = chunk->u.next)
	{
	  if (!chunk->crumb)
	    {
	      BlueProcessCrash ("Found a crumb\n") ;
	    }
	  else
	    chunk->crumb = BLUE_FALSE ;
	}
    }

  BlueUnlock (binheap_lock) ;
}
#endif

BLUE_VOID BlueHeapInitImpl (BLUE_VOID)
{
  struct binheap_chunk * chunk ;
  BLUE_INT i ;
#if defined(_WINCE_) 
  DWORD size ;
#endif
#if defined(__ANDROID__) || defined(ANDROID) || defined(__linux__) || defined(__APPLE__)
  size_t size ;
#endif

  for (i = 0 ; i < BLUE_PARAM_HEAP_POWER + 1 ; i++)
    {
      binheap[i] = BLUE_NULL ;
    }

#if defined(_WINCE_)
  size = (1 << BLUE_PARAM_HEAP_POWER) ;

  heap = (BLUE_UINT32 *) VirtualAlloc (0, size, MEM_RESERVE, PAGE_NOACCESS);
  heap = (BLUE_UINT32 *) VirtualAlloc (heap, size, MEM_COMMIT, PAGE_READWRITE);
  chunk = (BLUE_VOID *) heap ;
#elif defined(__ANDROID__) || defined(ANDROID) || defined(__linux__) || defined(__APPLE__)
  size = (1 << BLUE_PARAM_HEAP_POWER) ;

  heap = (BLUE_UINT32 *) mmap(NULL, size, PROT_READ | PROT_WRITE,
			      MAP_PRIVATE | MAP_ANONYMOUS,
			      -1, 0) ;
  chunk = (BLUE_VOID *) heap ;
#else
  chunk = (BLUE_VOID *) heap ;
#endif

#if defined(BLUE_PARAM_HEAP_DEBUG)
  chunk->crumb = BLUE_TRUE ;
  chunk->alloc_size = 
    (1<<BLUE_PARAM_HEAP_POWER) - sizeof (struct binheap_chunk) ;
#endif
  binheap_power_free (BLUE_PARAM_HEAP_POWER, chunk) ;
  binheap_lock = BlueLockInit () ;
}

BLUE_VOID BlueHeapUnloadImpl (BLUE_VOID)
{
#if defined(_WINCE_) 
  DWORD size ;
#endif
#if defined(__ANDROID__) || defined(ANDROID) || defined(__linux__) || defined(__APPLE__)
  size_t size ;
#endif

#if defined(_WINCE_)
  size = (1 << BLUE_PARAM_HEAP_POWER) ;

  VirtualFree (heap, size, MEM_DECOMMIT);
  VirtualFree (0, size, MEM_RELEASE);
  heap = NULL ;
#elif defined(__ANDROID__) || defined(ANDROID) || defined(__linux__) || defined(__APPLE__)
  size = (1 << BLUE_PARAM_HEAP_POWER) ;

  munmap (heap, size);
  heap = NULL ;
#endif
  BlueLockDestroy (binheap_lock) ;
}

BLUE_LPVOID BlueHeapMallocImpl (BLUE_SIZET size)
{
  BLUE_INT power ;
  struct binheap_chunk * chunk ;
  BLUE_LPVOID mem ;

  if (size > 100000)
    BlueProcessCrash ("Allocating something huge\n") ;

  power = binheap_power_find (size + sizeof(struct binheap_chunk)) ;
  chunk = binheap_power_alloc (power, size) ;

  mem = (BLUE_LPVOID) (++chunk) ;

#if defined(BLUE_PARAM_HEAP_CHECK)
  binheap_debug_check() ;
#endif
  return (mem) ;
}

BLUE_VOID BlueHeapCheckAllocImpl (BLUE_LPCVOID mem)
{
#if defined(BLUE_PARAM_HEAP_DEBUG)
  const struct binheap_chunk * chunk ;

  if (mem != BLUE_NULL)
    {
      chunk = mem ;
      chunk-- ;

      binheap_check_alloc (chunk) ;
    }
#endif
}

BLUE_VOID BlueHeapFreeImpl (BLUE_LPVOID mem)
{
  struct binheap_chunk * chunk ;

  if (mem != BLUE_NULL)
    {
      chunk = mem ;
      chunk-- ;

      binheap_power_free (chunk->u.power, chunk) ;
#if defined(BLUE_PARAM_HEAP_CHECK)
      binheap_debug_check() ;
#endif
    }
}

BLUE_LPVOID BlueHeapReallocImpl (BLUE_LPVOID ptr, BLUE_SIZET size)
{
  struct binheap_chunk * chunk ;
  struct binheap_chunk * newchunk ;
  BLUE_INT power ;

#if defined(BLUE_PARAM_HEAP_CHECK)
  binheap_debug_check() ;
#endif

  chunk = ptr ;
  power = binheap_power_find (size + sizeof(struct binheap_chunk)) ;

  if (chunk != BLUE_NULL)
    {
      chunk-- ;
      if (power > chunk->u.power)
	{
	  newchunk = binheap_power_alloc (power, size) ;
	  BlueCmemcpy (newchunk+1, chunk+1,
		       (1<<chunk->u.power) - sizeof (struct binheap_chunk)) ;

	  binheap_power_free (chunk->u.power, chunk) ;
	  chunk = newchunk ;
	}
#if defined(BLUE_PARAM_HEAP_DEBUG)
      else
	{
	  BLUE_CHAR *unused ;
	  chunk->alloc_size = size ;
	  /*
	   * Let's Make a Fence
	   */
	  for (unused = (BLUE_CHAR *) (chunk + 1) + chunk->alloc_size ;
	       unused < (BLUE_CHAR *) (chunk) + (1<<chunk->u.power) ;
	       unused++)
	    *unused = BLUE_HEAP_FENCE ;
	}
#endif
    }
  else
    {
      chunk = binheap_power_alloc (power, size) ;
    }

  chunk++ ;
#if defined(BLUE_PARAM_HEAP_CHECK)
  binheap_debug_check() ;
#endif
  return (chunk) ;
}

