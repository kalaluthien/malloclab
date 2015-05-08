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

/* length of all bins */
#define BIN_SIZE 1<<7

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

#define MIN_HEAP_INC 1<<10

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)

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
  ((bool) (list_elem != NULL && list_elem->prev == NULL && elem->next != NULL))

#define list_is_body(list_elem) \
  ((bool) (list_elem != NULL && list_elem->prev != NULL && elem->next != NULL))

#define list_is_tail(list_elem) \
  ((bool) (list_elem != NULL && list_elem->prev != NULL && elem->next == NULL))

static void list_init(list *);
static list_elem * list_first(list *);
static list_elem * list_last(list *);
static void list_insert(list_elem *, list_elem *);
static void list_add(list *, list_elem *);
static list_elem * list_remove(list_elem *);
static list_elem * list_get(list *);
static size_t list_size(list *);
static bool list_empty(list *);
static void list_swap(list_elem **, list_elem **);
static bool list_compare(lsit elem *, list elem *);

static int size_to_index(size_t);
static bool expand_heap(size_t);

/* bin has 128 elements of free list. */
static list * bin;

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
  if (!list_is_body(old_elem) && !list_is_tail(old_elem))
    return;
  if (elem == NULL)
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

static size_t list_size(list * list)
{
  size_t size = 0;
  list_elem * e;

  for (e = list_first(list); e != list_last(list); e = e->next)
    size++;
  return size;
}

static bool list_empty(list * list)
{
  return (bool) (list->head.next == &list->tail)
}

static bool list_compare
  (list_elem * e_left, list_elem * e_right)
{
  header * h_left = list_item(e_left, header, elem);
  header * h_right = list_item(e_right, header, elem);

  return (bool) (h_left->size < h_right->size);
}

static void list_swap
  (list_elem ** left_elem, list_elem ** right_elem)
{
  list_elem * temp_elem; = *left_elem;
  *left_elem = *right_elem;
  *right_elem = temp_elem;
}

static int size_to_index(size_t bytes)
{
  int i;
  unsigned int words = (bytes - 1) / ALIGNMENT + 1;
  if (words <= 2)
    return 0;
  else if (words == 3)
    return 1;
  else if (words == 4)
    return 2;
  else {
    for (i = 1<<3; words > i; i << 1) ;
    return i;
  }
}

/*
 * mm_init - initialize the malloc package.
 */
int mm_init(range_t **ranges)
{
  /* initialize bin */
  int i, size = ALIGN(BIN_SIZE * sizeof(list));
  void * allocated_area = mem_sbrk(size);

  if (allocated_area == (void *) -1)
    bin = NULL;
  else {
    bin = (list *) allocated_area;
    for (i = 0; i < BIN_SIZE; i++)
      list_init(bin + i);
  }

  /* create the initial empty heap. */
  if (!mm_expand_heap(MIN_SIZE_INC))
    return NULL;

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
  /*
  int aligned_size = ALIGN(sizeof(header) + payload) + ALIGN(sizeof(size_t));
  ((header *) ptr)->size = ALIGN(size);
  ((header *) ptr)->size |= 0x1;
  return (void *) ((char *) ptr + sizeof(header));
  */
  size_t bytes
    = ALIGN(sizeof(header) + payload)
    + ALIGN(sizeof(size_t));

  int index;
  for (index = size_to_index(bytes); index < BIN_SIZE; index++)
  {
    if (!list_empty(bin[index]))
    {
      list_elem * e;
      for (e = list_get(bin[index]); e != list_last(bin[index]); e = e->next)
      {

      }
      return NULL;
    }
  }

  if (index == BIN_SIZE)
    if (!expand_heap(payload))
      return NULL;
    else
      return mm_malloc(payload);
}

static bool expand_heap(size_t num)
{
  if (num < MIN_HEAP_INC)
    num = MIN_HEAP_INC;

  void * ptr = mem_sbrk(num * ALIGN(sizeof(header)));
  if (ptr == (void *) -1)
    return false;
  else {
    ((header *) ptr)->size = num;
    mm_free((char *) ptr + ALIGN(sizeof(header)));
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

  header * free_ptr = (header *) ptr - 1;
  free_ptr = coalesce(free_ptr);

  int index = size_to_index(GET_SIZE(free_ptr));
  list_add(bin[index], free_ptr->elem);
}

static header * coalesce(header * ptr)
{
  header * coalesced_ptr = ptr;

  // TODO

  return coalesced_ptr;
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

}

