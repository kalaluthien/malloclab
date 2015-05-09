/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 *
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
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

/* length of all free_bins */
#define BIN_SIZE 128

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

#define MIN_HEAP_INC 1024

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)

/* minimum malloc block size. */
#define MIN_MALLOC (ALIGN(sizeof(header) + sizeof(size_t)))

/* find the offset of member of a struct. */
#define OFFSET_OF(type, member) ((size_t) &((type *) 0)->member)

/* take values for header. */
#define GET_SIZE(h) (((header *) h)->size & ~0x7)

#define GET_ALLOC(h) (((header *) h)->size & 0x3)

#define GET_HEADER(p) ((header *) p - 1)

/* use hand-made boolean. */
typedef signed char bool;
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

/*
 * macro functions which are used to get ptr to STRUCT from its LIST_ELEM.
 * using example:
 *   struct block * new_block;
 *   new_block = list_get(old_block->member, struct block, member);
 */
#define list_item(list_elem, type, member) \
  ((type *) ((char *) &(list_elem)->next - OFFSET_OF(type, member.next)))

/* check the position of elem. */
#define list_is_head(list_elem) \
  ((bool) (list_elem != NULL && list_elem->prev == NULL && list_elem->next != NULL))

#define list_is_body(list_elem) \
  ((bool) (list_elem != NULL && list_elem->prev != NULL && list_elem->next != NULL))

#define list_is_tail(list_elem) \
  ((bool) (list_elem != NULL && list_elem->prev != NULL && list_elem->next == NULL))

static void list_init(list *);
static list_elem * list_first(list *);
static list_elem * list_last(list *);
static void list_insert(list_elem *, list_elem *);
static void list_add(list *, list_elem *);
static list_elem * list_remove(list_elem *);
static list_elem * list_get(list *);
//static size_t list_size(list *);
static bool list_empty(list *);
//static void list_swap(list_elem **, list_elem **);
static bool list_compare(list_elem *, list_elem *);
static int size_to_index(size_t);
static void * get_fit_block(list *, size_t);
static void split_block(header *, size_t);
static bool expand_heap(size_t);
static header * coalesce_block(header *);

/* array of free lists. */
static list * free_bin;

/* alloc list. */
static list alloc_list;

/* for debugging. */
static int debug_count;
static bool debug_flag = false;

static void deb(void)
{
  if (debug_flag)
    printf("==== Debug Point : (%d)\n", ++debug_count);
}

static void prt(const char * str, unsigned int num)
{
  if (debug_flag)
    printf("==== %s : %d\n", str, num);
}

static void msg(const char * str)
{
  if (debug_flag)
    printf("==== %s : (%d)\n", str, ++debug_count);
}

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

static void list_init(list * list)
{
  if (list == NULL)
    return;

  list->head.prev = NULL;
  list->head.next = &list->tail;
  list->tail.prev = &list->head;
  list->tail.next = NULL;
}

static list_elem * list_first(list * list)
{
  if (list == NULL)
    return NULL;
  else
    return list->head.next;
}

static list_elem * list_last(list * list)
{
  if (list == NULL)
    return NULL;
  else
    return list->tail.prev;
}

static void list_insert
  (list_elem * old_elem, list_elem * elem)
{
  if (list_is_head(old_elem) || elem == NULL)
    return;

  elem->prev = old_elem->prev;
  elem->next = old_elem;
  old_elem->prev->next = elem;
  old_elem->prev = elem;
}

static void list_add(list * list, list_elem * elem)
{
  list_elem * e;
  for (e = list_first(list); e != list_last(list); e = e->next)
    if (list_compare(elem, e))
      break;

  list_insert(e, elem);
}

static list_elem * list_remove(list_elem * elem)
{
  if (!list_is_body(elem))
    return NULL;

  elem->prev->next = elem->next;
  elem->next->prev = elem->prev;
  return elem->next;
}

static list_elem * list_get(list * list)
{
  list_elem * list_front = list_first(list);
  list_remove(list_front);
  return list_front;
}
/*
static size_t list_size(list * list)
{
  size_t size = 0;
  list_elem * e;

  for (e = list_first(list); e != list_last(list); e = e->next)
    size++;
  return size;
}
*/
static bool list_empty(list * list)
{
  return (bool) (list->head.next == &list->tail);
}

static bool list_compare
  (list_elem * e_left, list_elem * e_right)
{
  header * h_left = list_item(e_left, header, elem);
  header * h_right = list_item(e_right, header, elem);

  return (bool) (h_left->size < h_right->size);
}
/*
static void list_swap
  (list_elem ** left_elem, list_elem ** right_elem)
{
  list_elem * temp_elem = *left_elem;
  *left_elem = *right_elem;
  *right_elem = temp_elem;
}
*/
static void list_print(list * list)
{
  int i;
  list_elem * e;
  for (e = list_first(list), i = 1; ; e = e->next, i++)
    if (list_is_head(e))
      printf("|h|");
    else if (list_is_body(e))
      printf("<->|%d|", i);
    else
    {
      printf("<->|t|\n");
      break;
    }
}

static void bin_print()
{

  // TODO

}

static int size_to_index(size_t bytes)
{
  int i;
  unsigned int words = (bytes - 1) / ALIGNMENT + 1;
  prt("stoi_words", words);
  if (words <= 2)
    return 0;
  else if (words == 3)
    return 1;
  else if (words == 4)
    return 2;
  else {
    for (i = 8; i < words; i = i << 1) ;
    return i;
  }
}

/*
 * mm_init - initialize the malloc package.
 */
int mm_init(range_t **ranges)
{
  debug_flag = true;
  printf("\n\n");
  msg("mm_init start...");
  /* initialize free_bin of free lists. */
  size_t size = ALIGN(BIN_SIZE * sizeof(list));
  void * allocated_area = mem_sbrk(size);

  msg("mm_init bin...");
  if (allocated_area == (void *) -1)
    free_bin = NULL;
  else {
    free_bin = (list *) allocated_area;

    int i;
    for (i = 0; i < BIN_SIZE; i++)
      list_init(free_bin + i);
  }

  msg("mm_init alloc list...");
  /* initialize alloc list. */
  list_init(&alloc_list);

  msg("mm_init expand heap...");
  /* create the initial empty heap. */
  if (!expand_heap(MIN_HEAP_INC))
    return -1;

  /* DON't MODIFY THIS STAGE AND LEAVE IT AS IT WAS */
  gl_ranges = ranges;

  msg("mm_init over...");
  debug_flag = false;
  return 0;
}

/*
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void * mm_malloc(size_t payload)
{
  /*
  ((header *) ptr)->size = ALIGN(size);
  ((header *) ptr)->size |= 0x1;
  */
  void * ret_ptr;

  /* set bytes for allocate, considering minimum value. */
  size_t bytes = ALIGN(sizeof(header) + payload);
  if (bytes < MIN_MALLOC)
    bytes = MIN_MALLOC;

  /* search best fit block from small size class. */
  int index = size_to_index(bytes);
  for (; index < BIN_SIZE; index++)
  { // for lists in free_bin.
    if (!list_empty(&free_bin[index]))
      if ((ret_ptr = get_fit_block(&free_bin[index], bytes)) != NULL)
        return ret_ptr;
  }

  /* get more space when failed to allocate proper block. */
  if (!expand_heap(payload))
    return NULL;
  else
    return mm_malloc(payload);
}

static void * get_fit_block(list * list, size_t bytes)
{
  list_elem * e = list_get(list);
  for (; !list_is_tail(e); e = e->next)
  { // for list_elems.
    header * e_block = list_item(e, header, elem);

    /* do not match. */
    if (e_block->size < bytes)
      continue;

    /* match. */
    else if (e_block->size > bytes)
      split_block(e_block, bytes);

    list_remove(e);
    list_add(&alloc_list, e);
    return (void *) (e_block + 1);
  }
  /* do not match at all. */
  return NULL;
}

static void split_block(header * block, size_t bytes)
{

  // TODO

}

static bool expand_heap(size_t bytes)
{
  msg("expand_heap setting...");
  /* make bytes larger than or equal to minimum value. */
  if (bytes < MIN_HEAP_INC)
    bytes = MIN_HEAP_INC;

  /* expand heap. */
  void * ptr = mem_sbrk(ALIGN(bytes));
  msg("mem_sbrk done...");
  if (ptr == (void *) -1)
    return false;
  else {
    ((header *) ptr)->size = bytes;
    mm_free((char *) ptr + ALIGN(sizeof(header)));
    msg("expand_heap added new block to free list");
    return true;
  }
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void * ptr)
{
  if (gl_ranges)
    remove_range(gl_ranges, ptr);

  msg("mm_free setting...");
  header * free_ptr = (header *) ptr - 1;
  msg("mm_free got header...");
  list_remove(&free_ptr->elem);
  msg("mm_free removed block from alloc_list...");
  free_ptr = coalesce_block(free_ptr);
  msg("mm_free coalescing...");

  int index = size_to_index(GET_SIZE(free_ptr));
  msg("mm_free setting to add block to list...");
  list_add(&free_bin[index], &free_ptr->elem);
  msg("mm_free added block to free list...");
}

static header * coalesce_block(header * block)
{
  header * coalesced_block = block;

  // TODO

  return coalesced_block;
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
 */
void mm_exit(void)
{
  list_elem * e = list_first(&alloc_list);
  while (!list_is_tail(e))
  {
    e = e->next;
    mm_free(e->prev + 1);
  }
}
