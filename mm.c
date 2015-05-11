/*
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
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

/* default sizes for bin, expanding heap. */
#define BIN_SIZE 90
#define MIN_HEAP_INC 1<<10

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)

/* minimum malloc block size. */
#define MIN_MALLOC (ALIGN(sizeof(header) + ALIGN(sizeof(footer))))

/* find the offset of member of a struct. */
#define OFFSET_OF(type, member) ((size_t) &((type *) 0)->member)

/* take values for header. */
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

#define NONE 0x0
#define ALLOCATED 0x1
#define ADJUST_ALLOCATED 0x2

#define IS_ALLOCATED(h) \
  ((GET_ALLOC(h) & ALLOCATED) ? true : false)

#define IS_ADJUST_ALLOCATED(h) \
  ((GET_ALLOC(h) & ADJUST_ALLOCATED) ? true : false)

/* use hand-made boolean. */
typedef char bool;
#define true 1
#define false 0

/* enum to implement redblack tree. */
typedef enum {
  BLACK, RED
} rb_color;

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
  rb_color color;
} footer;

/*
 * macro functions which are used to get ptr to STRUCT from its LIST_ELEM.
 * using example for :
 *   struct block * new_block;
 *   new_block = list_get(&old_block->m_name, struct block, m_name);
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

/* tree functions equal to list functions. */
#define tree_item(tree_elem, type, member) \
  ((type *) ((char *) &(tree_elem)->next - OFFSET_OF(type, member.next)))

#define tree_init(tree) list_init(tree)
#define tree_root(tree) list_first(tree)
#define tree_empty(tree) list_empty(tree)

/* list operations. */
static void list_init(list *);
static list_elem * list_first(list *);
static void list_add(list *, list_elem *);
static list_elem * list_remove(list_elem *);
static bool list_empty(list *);

/* rbtree operations. */
static void tree_insert(list *, list_elem *);
static list_elem * tree_retrieve(list *, size_t);
static list_elem * tree_remove(list_elem *);

/* private functions. */
static int size_to_index(size_t);
static void set_free_state(header *);
static header * get_fit_block(list *, size_t);
static header * split_block(header *, size_t);
static bool expand_heap(size_t);
static void arrange_block(header *);
static header * coalesce_block(header *);

/* array of free lists. */
static list * free_bin;

/* alloc list. */
static list alloc_list;

/* for debugging. */
static int debug_indent;
static int debug_count;
static bool debug_flag;

static void df(bool flag)
{
  debug_flag = flag;
}

static void inc(void)
{
  debug_indent++;
}

static void dec(void)
{
  debug_indent--;
}

static void prti(void)
{
  int i;
  for (i = 0; i < debug_indent; i++)
    printf(" | ");
}

static void dc(void)
{
  if (debug_flag)
  {
    prti();
    printf(" Debug Point : (%d)\n", ++debug_count);
  }
}

static void prt(const char * str, long long num)
{
  if (debug_flag)
  {
    prti();
    printf(" %s : %lld\n", str, num);
  }
}

static void prtp(const char * str, void * ptr)
{
  if (debug_flag)
  {
    prti();
    printf(" %s : %p\n", str, ptr);
  }
}

static void msg(const char * str)
{
  if (debug_flag)
  {
    prti();
    printf(" %s\n", str);
  }
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

/*
 * list functions - used to maipulate linked list.
 *  used for alloc_list. (allocated block list)
 */
static void list_init(list * list)
{
  list->head.prev = NULL;
  list->head.next = &list->tail;
  list->tail.prev = &list->head;
  list->tail.next = NULL;
}

static list_elem * list_first(list * list)
{
  return list->head.next;
}

static void list_add(list * list, list_elem * elem)
{
  list_elem * e = list_first(list);

  elem->prev = e->prev;
  elem->next = e;
  e->prev->next = elem;
  e->prev = elem;
}

static list_elem * list_remove(list_elem * elem)
{
  if (!list_is_body(elem))
    return NULL;

  elem->prev->next = elem->next;
  elem->next->prev = elem->prev;
  return elem->next;
}

static bool list_empty(list * list)
{
  return (bool) (list->head.next == &list->tail);
}

/*
 * tree functions - used to manipulate redblack tree.
 *  used for free_bin[index]. (array of free block list)
 */

static list_elem * tree_insert_rec(list_elem *, list_elem *, list_elem *);
/*
static void tree_insert(list * tree, list_elem * elem)
{
  list_elem * root = tree_root(tree);
  tree_insert_rec(root, elem, &tree->tail);
}

static list_elem * tree_insert_rec
  (list_elem * root, list_elem * elem, list_elem * nil)
{
  if (root == nil)
    // TODO

}

static list_elem * tree_retrieve(list * tree, size_t size)
{
  list_elem * root = tree_root(tree);
  return tree_retrieve(root, size, &tree->tail);
}

static list_elem * tree_retrieve(list_elem * elem, size_t size, list_elem * nil)
{
  if (elem == nil)
    return NULL;

  header * block = (tree_item(elem, header,

}

static list_elem * tree_remove(list_elem * elem)
{

}
*/
/* utility functions. */
static int size_to_index(size_t bytes)
{
  unsigned int words = (bytes - 1) / ALIGNMENT + 1;
  if (words <= 64)
    return words - 2;
  else
  {
    int i = 1, j = 8;
    for (words -= 64; j < words; i++, j <<= 1) ;
    return i + 62;
  }
}

static void set_free_state(header * block)
{
  block->size >>= 1;
  block->size <<= 1;
}

/*
 * mm_init - initialize the malloc package.
 */
int mm_init(range_t ** ranges)
{
  //df(true);
  msg("<init called>");

  /* initialize free_bin of free lists and allocate space for dummy block. */
  size_t size
    = ALIGN(BIN_SIZE * sizeof(list))                  // bin[BIN_SIZE].
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
    = (header *) ((char *) allocated_area + ALIGN(BIN_SIZE * sizeof(list)));
  dummy_head->size = MIN_MALLOC | ALLOCATED;
  GET_FOOTER(dummy_head)->size = MIN_MALLOC | ALLOCATED;

  header * dummy_tail
    = (header *) ((char *) allocated_area + size - ALIGN(sizeof(header)));
  dummy_tail->size = ALIGN(sizeof(size_t)) | ADJUST_ALLOCATED | ALLOCATED;

  /* initialize alloc list. */
  list_init(&alloc_list);

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

  inc();
  msg("<malloc called>");

  /* set bytes for allocate, considering minimum value. */
  size_t bytes = ALIGN(sizeof(header)) + ALIGN(payload);
  if (bytes < MIN_MALLOC)
    bytes = MIN_MALLOC;

  /* search best fit block from small size class. */
  int index = size_to_index(bytes);
  while (true)
  {
    /* search best-fit free block. */
    if (!list_empty(&free_bin[index]))
    {
      msg("<malloc calls search>");
      ret_block = get_fit_block(&free_bin[index], bytes);
      if (ret_block != NULL)
      {
        /* set allocate states. */
        ret_block->size |= ALLOCATED;
        GET_NEXT(ret_block)->size |= ADJUST_ALLOCATED;

        prt("<malloc found block in bin[index]>", index);
        dec();

        return GET_PAYLOAD(ret_block);
      }
    }

    /* get more space when failed to allocate proper block. */
    if (++index == BIN_SIZE)
    {
      msg("<malloc calls expand>");
      if (!expand_heap(bytes))
        return NULL;
      else
        index = size_to_index(bytes);
      msg("<malloc get return expand>");
    }
  }
}

/*
 * get_fit_block - Search a best fit block by check all blocks in list
 *  and return it.
 */
static header * get_fit_block(list * list, size_t bytes)
{
  inc();
  msg("<search called>");

  header * fit_block = NULL;

  list_elem * e;
  for (e = list_first(list); !list_is_tail(e); e = e->next)
  {
    header * e_block = list_item(e, header, elem);

    /* check if e_block is big enough to match. */
    if (e_block->size >= bytes)
    {
      msg("<search found enough block>");
      /* exact size. */
      if (e_block->size < bytes + MIN_MALLOC)
      {
        list_remove(e);
        list_add(&alloc_list, e);
        dec();
        return e_block;
      }

      /* bigger size. */
      else if (fit_block == NULL || fit_block->size > e_block->size)
          fit_block = e_block;
    }
  }

  /* allocate big block after spliting.  */
  if (fit_block != NULL)
  {
    msg("<search calls split>");
    fit_block = split_block(fit_block, bytes);
    list_add(&alloc_list, &fit_block->elem);
    msg("<search get return split>");
  }

  dec();
  return fit_block;
}

/*
 * split_block - Split a one block to two adjust blocks.
 *  Return a pointer to header of second block.
 */
static header * split_block(header * block, size_t bytes)
{
  inc();
  msg("<split called>");
  prt("<split origin block size>", GET_SIZE(block));

  /* handle first block which remains in the free list. */
  block->size -= bytes;
  GET_FOOTER(block)->size = GET_SIZE(block);

  prt("<split first block size>", GET_SIZE(block));

  /* handle second block which allocated to user. */
  block = GET_NEXT(block);
  block->size = bytes | ALLOCATED;
  GET_FOOTER(block)->size = block->size;

  prt("<split second block size>", GET_SIZE(block));

  msg("<split calls arrange>");
  /* rearrange first block. */
  list_remove(&GET_PREV(block)->elem);
  arrange_block(GET_PREV(block));

  msg("<split get return arrange>");
  prt("<splt rearranged first block size>", GET_SIZE(GET_PREV(block)));

  /* set allocated status of the next block. */
  GET_NEXT(block)->size |= ADJUST_ALLOCATED;

  dec();
  return block;
}

static bool expand_heap(size_t bytes)
{
  inc();
  msg("<expand called>");
  prt("<expand demand(bytes)>", bytes);

  /* make bytes aligned and larger than or equal to minimum value. */
  bytes = ALIGN(bytes);
  if (bytes < ALIGN(MIN_HEAP_INC))
    bytes = ALIGN(MIN_HEAP_INC);

  prt("<expand aligned(bytes)>", bytes);

  /* expand heap using mem_sbrk. */
  void * ptr = mem_sbrk(bytes);
  if (ptr == (void *) -1)
    return false;
  else
  {
    header * area = GET_HEADER(ptr);
    area->size
      = bytes
      | (IS_ADJUST_ALLOCATED(area) ? ADJUST_ALLOCATED : NONE);
    GET_FOOTER(area)->size = bytes;

    /* set dummy tail block. */
    GET_NEXT(area)->size = ALIGN(sizeof(header)) | ALLOCATED;

    msg("<expand set chunk>");
    msg("<expand calls arrange>");

    arrange_block(area);

    msg("<expand get return arrange>");
    dec();

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

  header * free_block = GET_HEADER(ptr);

  inc();
  msg("<free called>");

  /* remove from alloc list. */
  if (list_remove(&free_block->elem) == NULL)
    return;
  msg("<free removed block from alloc_list>");

  msg("<free calls arrange>");
  arrange_block(free_block);

  msg("<free arrange done>");
  dec();
}

static void arrange_block(header * free_block)
{
  inc();
  msg("<arrange called>");
  msg("<arrange calles coalesce>");
  /* set free and coalescing blocks. */
  set_free_state(free_block);
  free_block = coalesce_block(free_block);
  msg("<arrange get return coalesce>");

  /* add to free list. */
  int index = size_to_index(GET_SIZE(free_block));
  list_add(&free_bin[index], &free_block->elem);

  prt("<arrange add block to bin[index]>", index);
  dec();
}

static header * coalesce_block(header * block)
{
  header * merged_block = block;

  inc();
  msg("<coalesce called>");

  /* merge with previous block. */
  if (!IS_ADJUST_ALLOCATED(block))
  {
    /* retreive previous block. */
    merged_block = GET_PREV(block);
    list_remove(&merged_block->elem);

    /* merge blocks. */
    merged_block->size += block->size;
    GET_FOOTER(block)->size = GET_SIZE(merged_block);

    msg("<coalesce merge previous>");
  }

  /* merge with next block. */
  if (!IS_ALLOCATED(GET_NEXT(merged_block)))
  {
    /* retreive next block. */
    block = GET_NEXT(block);
    list_remove(&block->elem);

    /* merge blocks. */
    merged_block->size += GET_SIZE(block);
    GET_FOOTER(block)->size = GET_SIZE(merged_block);

    msg("<coalesce merge next>");
  }

  dec();
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
 */
void mm_exit(void)
{
  msg("<mm_exit called>");

  list_elem * e = list_first(&alloc_list);
  while (!list_is_tail(e))
  {
    e = e->next;
    header * block = list_item(e->prev, header, elem);
    mm_free(GET_PAYLOAD(block));
  }

  msg("<mm_exit handled memory leak>");
  dec();
}
