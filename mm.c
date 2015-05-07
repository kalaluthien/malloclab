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
#define BIN_SIZE 128

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)

/* find the offset of member of a struct. */
#define OFFSET_OF(type, member) ((size_t) &((type *) 0)->member)

#define GET_SIZE(p) (*((size_t *) p) & ~0x7)

#define GET_ALLOC(p) (*((size_t *) p) & 0x3)

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
  list_elem elem;
} list;

/* Block header. */
typedef struct {
  size_t size;
  list_elem elem;
} header;

/*
 * macro function which used to get ptr to STRUCT from its LIST_ELEM.
 * using example:
 *   struct block * new_block;
 *   new_block = list_get(old_block->member, struct block, member);
 */
#define list_item(list_elem, type, member) \
  ((type *) ((char *) &(list_elem)->next - OFFSET_OF(type, member.next)))

#define list_is_head(list_elem) \
  ((bool) (list_elem != NULL && list_elem->prev == NULL && elem->next != NULL))

#define list_is_body(list_elem) \
  ((bool) (list_elem != NULL && list_elem->prev != NULL && elem->next != NULL))

#define list_is_tail(list_elem) \
  ((bool) (list_elem != NULL && list_elem->prev != NULL && elem->next == NULL))

static void list_init(list *);
/*
static list_elem * list_begin(list *);
static list_elem * list_next(list_elem *);
static list_elem * list_prev(list_elem *);
static list_elem * list_end(list *);
static void list_insert(list_elem *, list_elem *);
static void list_push(list *, list_elem *);
static list_elem * list_delete(list_elem *);
static list_elem * list_pop(list *);
static size_t list_size(list *);
static int list_is_exist(list *);
static void list_swap(list elem **, list elem **);
*/

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

static list_elem * list_begin(list * list)
{
  if (list == NULL)
    return NULL;
  else
    return list->head.next;
}

static list_elem * list_next(list_elem * elem)
{
  if (list_is_tail(elem))
    return NULL;
  else
    return elem->next;
}

static list_elem * list_prev(list_elem * elem)
{
  if(list_is_head(elem))
    return NULL;
  else
    return elem->prev;
}

static list_elem * list_end(list * list)
{
  if (list == NULL)
    return NULL;
  else
    return list->tail.prev;
}

static void list_insert
  (list_elem * left_elem, list_elem * elem)
{


}

static void list_push(list * list, list_elem * elem)
{



}

static list_elem * list_delete(list_elem * elem)
{

  return elem;
}

static list_elem * list_pop(list * list)
{

  return NULL;
}

static size_t list_size(list * list)
{

  return 0;
}

static void list_swap
  (list_elem ** left_elem, list_elem ** right_elem)
{

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

  /* DON't MODIFY THIS STAGE AND LEAVE IT AS IT WAS */
  gl_ranges = ranges;

  return 0;
}

/*
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void * mm_malloc(size_t size)
{
  int newsize = HEADER_SIZE + ALIGN(size) + SIZE_T_SIZE;
  void * ptr = mem_sbrk(newsize);
  if (ptr == (void *)-1)
    return NULL;
  else {
    ((header *) ptr)->size = ALIGN(size);
    ((header *) ptr)->size |= 0x1;
    return (void *) ((char *) ptr + HEADER_SIZE);
  }
}

header * mm_expand_heap(size_t num)
{
  int newsize = HEADER_SIZE + ALIGN(size) + SIZE_T_SIZE;
  void * ptr = mem_sbrk(newsize);
  if (ptr == (void *)-1)
    return NULL;
  else {
    ((header *) ptr)->size = ALIGN(size);
    ((header *) ptr)->size |= 0x1;
    return (void *) ((char *) ptr + HEADER_SIZE);
  }

  return NULL;
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void * ptr)
{


  /* DON't MODIFY THIS STAGE AND LEAVE IT AS IT WAS */
  if (gl_ranges)
    remove_range(gl_ranges, ptr);
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

