/*
 *  mm.c -
 *  copyright
 *
 *
 *
 *
____Strcuture of free block______________________________________

                          0 a b   a: previous block is allocated
    +--------------------+-+-+-+
 h  |    size:           |0|x|0|  b: this block is allocated
 e  +--------------------+-+-+-+
 a  |    list_elem:            |  pointer for linking free list
 d  |      prev, next          |
    +--------------------------+
    |                          |
    |      :                   |
    |      :                   |
    |    payload               |
    |      :                   |
    |      :                   |
 f  |                          |
 o  +--------------------+-+-+-+
 o  |    size:           |0|0|0|
 t  +--------------------+-+-+-+
                          0 0 b

  Free block consists of three component:
  header, footer, and payload.

  1. Header
    The header has informations of the free block.
    It has two member: size, list_elem.

    The size member shows block size include all parts of the block.
    (header + payload + footer)
    And because all blocks are aligned by single word or double word,
    two least significant bits are used to disignate allocated states.
    In this file, adjust allocated status are used to increase utilization.

    The list_elem member just points other list_elems.

     elem      elem      elem
    +----+    +----+    +----+
    |    | <- |    | -> |    |
    +----+    +----+    +----+

    By apply some pointer arithmatics, pointer to header can be
    obtained. - using macro functions(OFFSET_OF(), list_item()).

     header
    +------+
    | size |
    +------+
    | elem |
    +------+

    In this file, linked list is implemented in that way.
    Free blocks are linked with their list_elem member.

  2. Footer
    The footer is replica of the header.
    It has just one memeber - size.
    It is used to get pointer to header.
    Each block can get previous free block using
    footer->size of previous block.

  3. Payload
    Empty spaces for free blocks.
    Maybe there are free blocks with size 0 payload.
_________________________________________________________________


____Structure of allocted block__________________________________

                          0 a b   a: previous block is allocated
    +--------------------+-+-+-+
 h  |    size:           |0|x|1|  b: block is allocated
 e  +--------------------+-+-+-+
 a  |    list_elem:            |  pointer for linking alloc list
 d  |      prev, next          |
    +--------------------------+
    |                          |
    |      :                   |
    |      :                   |
    |    payload               |
    |      :                   |
    |      :                   |
    |                          |
    |                          |
    |                          |
    +--------------------------+

  Allocated block consists of two component:
  header, and payload.

  1. Header
    The header has informations of the allocated block.
    Like free block, it has two member: size, list_elem.

    The size member shows block size include all parts of the block.
    But there are no footer for allocated block,
    it only counts header and payload.
    Also, size member has incoded allocation states.

    The list_elem member used to link blocks, ofcourse.
    mm_exit() frees all unfreed blocks using alloc_list.
    When there are members in alloc_list, there is memory leak.

  2. Payload
    The payload for allocated block includes spaces
    which called footer until the block is allocated.
    They are used to payload to increase mem util.
_________________________________________________________________


____Organization of the free list________________________________

  In this file, there are "free_bin" which hold array of free
  lists. Each class is sorted by block size. This makes efficient
  search for best fit block.

    free_bin
  +----+----+----+----+---      ---+----+----+----+----+
  | 00 | 01 | 02 | 03 |    ....    | 44 | 45 | 46 | 47 |
  +----+----+----+----+---      ---+----+----+----+----+
    ||   ||   ||                     ||   ||
   +--+ +--+ +--+                   +--+ +--+
   |  | |  | |  |                   |  | |  |
   +--+ +--+ +--+                   +--+ +--+
         ||   ||                     ||
        +--+ +--+                   +--+
        |  | |  |                   |  |
        +--+ +--+                   +--+
         ||                          ||
        +--+                        +--+
        |  |                        |  |
         ..                          ..

      free lists.

  There are slots for 32 small size classes and 16 big size classes.
  Each free list is related to unique bin slot. Small size classes
  are ordered in linear increase of size. Big size classes are
  ordered in exponential increase of size. Detail calculates are
  important for the performance.

  Free lists (and also allocation list) are implemeted to doubly
  linked list using 'list' and 'list_elem' structures.
  This doubly linked lists have two header elements: the "head"
  just before the first element and the "tail" just after the
  last element.  The `prev' link of the front header is null, as
  is the `next' link of the back header.
  Their other two links point toward each other via the interior
  elements of the list.

  An empty list looks like this:

                      +------+     +------+
                  /---| head |<--->| tail |---/
                      +------+     +------+

  A list with two elements in it looks like this:

        +------+     +-------+     +-------+     +------+
    /---| head |<--->|   1   |<--->|   2   |<--->| tail |---/
        +------+     +-------+     +-------+     +------+
_________________________________________________________________


____Algorithms for handling free lists___________________________

  When malloc() called, it make 'index' to free_bin. This
  is done by size_to_index() function. Next, malloc searches
  free_bin slots from free_bin[index] which are enough to
  allocate and not empty. After found proper free list,
  malloc get best fit block and return the pointer to block.

  The best fit algorithm takes O(n) times becuse if there are
  no small(do not have to split) blocks, it searches all blocks
  in the free list and finds the smallest.  But it does not search
  entire heap, so the overhead is not that bad.

  If the fit block is somewhat big, then split it into two
  saperated blocks. The block that is not allocated is
  re-arranged between free lists. (because the block size
  is changed)

  When free() called, free immediately coalesces free blocks
  using boundery tags. Merging with previous & next block takes
  O(1) time. The merged block then arranged to "free_bin" by
  its index(of course it uses size_to_index()).

  The insertion and removal for free list(and alloc_list) is
  done by simple list operations. Becuase the dummy blocks
  are allocated when mm_init() called, there are no corner cases.

_________________________________________________________________ */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your information in the following struct.
 ********************************************************/
team_t team = {
  /* Team name : Your student ID */
  "2013-11394",
  /* Your full name */
  "Hyungmo Kim",
  /* Your student ID */
  "2013-11394",
  /* leave blank */
  "",
  /* leave blank */
  ""
};

/* DON'T MODIFY THIS VALUE AND LEAVE IT AS IT WAS */
static range_t ** gl_ranges;

/* default sizes for bin, expanding heap. */
#define BIN_SIZE 48
#define FIXED_AREA 32
#define MIN_HEAP_INC ALIGN(1<<9)

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)

/* minimum malloc block size. */
#define MIN_MALLOC (ALIGN(sizeof(header) + ALIGN(sizeof(footer))))

/* find the offset of member of a struct. */
#define OFFSET_OF(type, member) ((size_t) &((type *) 0)->member)

/*
 * shorthand functions -take values from header and footer
 * using quite dirty pointer arithmatics.
 */
#define GET_SIZE(h) ((size_t) (((header *) h)->size & ~0x7))

#define GET_ALLOC(h) ((int) (((header *) h)->size & 0x3))

#define GET_FOOTER(h) \
  ((footer *) (((char *) h) + GET_SIZE(h) - ALIGN(sizeof(footer))))

#define GET_SIZE_FOOTER(h) (GET_FOOTER(h)->size & ~0x7)

#define GET_ALLOC_FOOTER(h) (GET_FOOTER(h)->size & 0x3)

#define GET_NEXT(h) ((header *) ((char *) h + GET_SIZE(h)))

#define GET_PREV(h) \
  ((header *) ((char *) h - \
  (((footer *) ((char *) h - ALIGN(sizeof(footer))))->size & ~0x7)))

#define GET_HEADER(p) ((header *) ((char *) p - ALIGN(sizeof(header))))

#define GET_PAYLOAD(p) ((void *) ((char *) p + ALIGN(sizeof(header))))

/* allocation states. */
#define NONE 0x0
#define ALLOCATED 0x1
#define ADJUST_ALLOCATED 0x2

/* allocation state operations. */
#define IS_ALLOCATED(h) \
  ((GET_ALLOC(h) & ALLOCATED) ? true : false)

#define IS_ADJUST_ALLOCATED(h) \
  ((GET_ALLOC(h) & ADJUST_ALLOCATED) ? true : false)

#define SET_ALLOC_FREE(block) block->size = (block->size & ~0x1)

/* use hand-made boolean. */
typedef char bool;
#define true 1
#define false 0

/* List element. */
typedef struct list_elem {
  struct list_elem * prev;
  struct list_elem * next;
} list_elem;

/* List. */
typedef struct {
  list_elem head;
  list_elem tail;
} list;

/* Block header. */
typedef struct {
  size_t size;
  list_elem elem;
} header;

/* Block footer. */
typedef struct {
  size_t size;
} footer;

/*
 * macro functions which are used to get ptr to STRUCT from its LIST_ELEM.
 *
 * using example for list_item:
 *   struct block * new_block;
 *   new_block = list_get(&old_block->m_name, struct block, m_name);
 */
#define list_item(list_elem, type, member) \
  ((type *) ((char *) &(list_elem)->next - OFFSET_OF(type, member.next)))

/* check the position of list_elem. */
#define list_is_head(list_elem) \
  ((bool) (list_elem != NULL && list_elem->prev == NULL && list_elem->next != NULL))

#define list_is_body(list_elem) \
  ((bool) (list_elem != NULL && list_elem->prev != NULL && list_elem->next != NULL))

#define list_is_tail(list_elem) \
  ((bool) (list_elem != NULL && list_elem->prev != NULL && list_elem->next == NULL))

/* list operations proto type. */
static void list_init(list *);
static list_elem * list_first(list *);
static void list_insert(list *, list_elem *);
static list_elem * list_remove(list_elem *);
static bool list_empty(list *);

/* private functions proto type. */
static int size_to_index(size_t);
static header * get_fit_block(list *, size_t);
static header * split_block(header *, size_t);
static bool expand_heap(size_t);
static void arrange_block(header *);
static header * coalesce_block(header *);

/* array of free lists. */
static list * free_bin;

/* pointer to alloc list. */
static list * alloc_list;

/*
 * remove_range - manipulate range lists
 * DON'T MODIFY THIS FUNCTION AND LEAVE IT AS IT WAS
 */
static void remove_range(range_t **ranges, char *lo)
{
  range_t *p;
  range_t **prevpp = ranges;

  if (!ranges)
    return;

  for (p = *ranges;  p != NULL; p = p->next) {
    if (p->lo == lo) {
      *prevpp = p->next;
      free(p);
      break;
    }
    prevpp = &(p->next);
  }
}

/*
 * list functions - used to maipulate linked list.
 *  used for alloc_list. (allocated block list)
 */

/* initiate list. */
static void list_init(list * list)
{
  list->head.prev = NULL;
  list->head.next = &list->tail;
  list->tail.prev = &list->head;
  list->tail.next = NULL;
}

/* return first object in the list. */
static list_elem * list_first(list * list)
{
  return list->head.next;
}

/* insert object to list. */
static void list_insert(list * list, list_elem * elem)
{
  list_elem * e = list_first(list);

  elem->prev = e->prev;
  elem->next = e;
  e->prev->next = elem;
  e->prev = elem;
}

/* remove object in the list. */
static list_elem * list_remove(list_elem * elem)
{
  /* return NULL if the object is not in the list. */
  if (!list_is_body(elem))
    return NULL;

  /* return next object for convinient repeatition. */
  elem->prev->next = elem->next;
  elem->next->prev = elem->prev;
  return elem->next;
}

/* return if the list is empty. */
static bool list_empty(list * list)
{
  return (bool) (list->head.next == &list->tail);
}

/* return appropriate index for aligned block size(bytes). */
static int size_to_index(size_t bytes)
{
  unsigned int words = (bytes - 1) / ALIGNMENT + 1;
  if (words <= FIXED_AREA)
    return words - 2;
  else
  {
    int i = 1, j = 1;
    for (words -= FIXED_AREA; j < words; i++, j <<= 1) ;
    return i + FIXED_AREA - 2;
  }
}

/*
 * mm_init - initialize the malloc package.
 *  initialize free_bin, alloc_list.
 *  also allocate dummy blocks.
 */
int mm_init(range_t ** ranges)
{
  /* initialize free_bin of free lists and allocate space for dummy blocks. */
  size_t size
    = ALIGN((BIN_SIZE + 1) * sizeof(list))            // free_bin and alloc_list.
    + ALIGN(sizeof(header)) + ALIGN(sizeof(footer))   // dummy head block.
    + ALIGN(sizeof(header));                          // dummy tail block.
  void * allocated_area = mem_sbrk(size);

  if (allocated_area == (void *) -1)
    return -1;
  else
  {
    free_bin = (list *) allocated_area;

    int index;
    for (index = 0; index < BIN_SIZE; index++)
      list_init(free_bin + index);
  }

  /* initialize dummy blocks. */
  header * dummy_head
    = (header *) ((char *) allocated_area + ALIGN((BIN_SIZE + 1) * sizeof(list)));
  dummy_head->size = MIN_MALLOC | ALLOCATED;
  GET_FOOTER(dummy_head)->size = MIN_MALLOC | ALLOCATED;

  header * dummy_tail
    = (header *) ((char *) allocated_area + size - ALIGN(sizeof(header)));
  dummy_tail->size = ALIGN(sizeof(size_t)) | ADJUST_ALLOCATED | ALLOCATED;

  /* initialize alloc list. */
  alloc_list
    = (list *) ((char *) allocated_area + ALIGN(BIN_SIZE * sizeof(list)));
  list_init(alloc_list);

  /* DON't MODIFY THIS STAGE AND LEAVE IT AS IT WAS */
  gl_ranges = ranges;
  return 0;
}

/*
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void * mm_malloc(size_t payload)
{
  header * ret_block;

  /* set bytes for allocate, considering minimum value. */
  size_t bytes = ALIGN(sizeof(header)) + ALIGN(payload);
  if (bytes < MIN_MALLOC)
    bytes = MIN_MALLOC;

  /* search best fit block from small size class. */
  int index = size_to_index(bytes);
  while (true)
  {
    if (!list_empty(&free_bin[index]))
    {
      /* search best-fit free block. */
      ret_block = get_fit_block(&free_bin[index], bytes);
      if (ret_block != NULL)
      {
        /* set allocate states. */
        ret_block->size |= ALLOCATED;
        GET_NEXT(ret_block)->size |= ADJUST_ALLOCATED;

        return GET_PAYLOAD(ret_block);
      }
    }

    /* get more space when failed to allocate proper block. */
    if (++index == BIN_SIZE)
    {
      if (!expand_heap(bytes))
        return NULL;
      else
        index = size_to_index(bytes);
    }
  }
}

/*
 * get_fit_block - Search a best fit block by check all blocks in list
 *  and return it.
 */
static header * get_fit_block(list * list, size_t bytes)
{
  header * fit_block = NULL;

  list_elem * e;
  for (e = list_first(list); !list_is_tail(e); e = e->next)
  {
    header * block = list_item(e, header, elem);

    /* check if block is big enough to match. */
    if (block->size >= bytes)
    {
      /* exact size. */
      if (block->size < bytes + MIN_MALLOC)
      {
        list_remove(e);
        list_insert(alloc_list, e);
        return block;
      }

      /* check big size blocks to find smallest. */
      else if (fit_block == NULL || fit_block->size > block->size)
          fit_block = block;
    }
  }

  /* allocate big block after spliting.  */
  if (fit_block != NULL)
  {
    fit_block = split_block(fit_block, bytes);
    list_insert(alloc_list, &fit_block->elem);
  }
  return fit_block;
}

/*
 * split_block - Split a one block to two adjust blocks.
 *  Return a pointer to header of second block.
 */
static header * split_block(header * block, size_t bytes)
{
  /* handle first block which remains in the free list. */
  block->size -= bytes;
  GET_FOOTER(block)->size = GET_SIZE(block);

  /* handle second block which allocated to user. */
  block = GET_NEXT(block);
  block->size = bytes | ALLOCATED;
  GET_FOOTER(block)->size = block->size;

  /* rearrange first block. */
  list_remove(&GET_PREV(block)->elem);
  arrange_block(GET_PREV(block));

  /* set allocated status of the next block. */
  GET_NEXT(block)->size |= ADJUST_ALLOCATED;

  return block;
}

/*
 * expand_heap - Call mem_sbrk() to demand more heap space.
 */
static bool expand_heap(size_t bytes)
{
  /* make bytes aligned and larger than or equal to minimum value. */
  bytes = ALIGN(bytes);
  if (bytes < MIN_HEAP_INC)
    bytes = MIN_HEAP_INC;

  /* expand heap using mem_sbrk. */
  void * ptr = mem_sbrk(bytes);
  if (ptr == (void *) -1)
    return false;
  else
  {
    /* set allocated area. */
    header * area = GET_HEADER(ptr);
    area->size
      = bytes
      | (IS_ADJUST_ALLOCATED(area) ? ADJUST_ALLOCATED : NONE);
    GET_FOOTER(area)->size = bytes;

    /* set dummy tail block. */
    GET_NEXT(area)->size = ALIGN(sizeof(header)) | ALLOCATED;

    /* put block to free list. */
    arrange_block(area);

    return true;
  }
}

/*
 * mm_free - Freeing a block does nothing.
 *  immideately coalesce adjust blocks to prevent fragmentation.
 */
void mm_free(void * ptr)
{
  if (gl_ranges)
    remove_range(gl_ranges, ptr);

  header * free_block = GET_HEADER(ptr);

  /* remove from alloc list. */
  if (list_remove(&free_block->elem) == NULL)
    return;

  arrange_block(free_block);
}

/*
 * arrange_block - Arranging merged block to appropriate free list.
 *  main part of free().
 */
static void arrange_block(header * free_block)
{
  /* set free and coalescing blocks. */
  SET_ALLOC_FREE(free_block);
  free_block = coalesce_block(free_block);

  /* add to free list. */
  int index = size_to_index(GET_SIZE(free_block));
  list_insert(&free_bin[index], &free_block->elem);
}

/*
 * coalesce_block - Coalescing adjust blocks.
 */
static header * coalesce_block(header * block)
{
  header * merged_block = block;

  /* merge with previous block. */
  if (!IS_ADJUST_ALLOCATED(block))
  {
    /* retreive previous block. */
    merged_block = GET_PREV(block);
    list_remove(&merged_block->elem);

    /* merge blocks. */
    merged_block->size += block->size;
    GET_FOOTER(block)->size = GET_SIZE(merged_block);
  }

  /* merge with next block. */
  if (!IS_ALLOCATED(GET_NEXT(block)))
  {
    /* retreive next block. */
    block = GET_NEXT(block);
    list_remove(&block->elem);

    /* merge blocks. */
    merged_block->size += GET_SIZE(block);
    GET_FOOTER(block)->size = GET_SIZE(merged_block);
  }

  return merged_block;
}

/*
 * mm_realloc - empty implementation; YOU DO NOT NEED TO IMPLEMENT THIS
 */
void * mm_realloc(void * ptr, size_t t)
{
  return ptr;
}

/*
 * mm_exit - finalize the malloc package.
 *  freeing all blocks in alloc_list.
 *  all malloced blocks are managed by alloc_list.
 */
void mm_exit(void)
{
  list_elem * e = list_first(alloc_list);
  while (!list_is_tail(e))
  {
    e = e->next;
    header * block = list_item(e->prev, header, elem);
    mm_free(GET_PAYLOAD(block));
  }
}
