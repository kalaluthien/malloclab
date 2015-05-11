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
#define BIN_SIZE 128
#define MIN_HEAP_INC 5096

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)

/* minimum malloc block size. */
#define MIN_MALLOC (ALIGN(sizeof(header) + ALIGN(sizeof(size_t))))

/* find the offset of member of a struct. */
#define OFFSET_OF(type, member) ((size_t) &((type *) 0)->member)

/* take values for header. */
#define GET_SIZE(h) ((size_t) (((header *) h)->size & ~0x7))

#define GET_ALLOC(h) ((int) (((header *) h)->size & 0x3))

#define GET_FOOTER(h) \
  ((size_t *) (((char *) h) + GET_SIZE(h) - ALIGN(sizeof(size_t))))

#define GET_SIZE_FOOTER(h) (*GET_FOOTER(h) & ~0x7)

#define GET_ALLOC_FOOTER(h) (*GET_FOOTER(h) & 0x3)

#define GET_NEXT(h) ((header *) ((char *) h + GET_SIZE(h)))

#define GET_PREV(h) \
  ((header *) ((char *) h - \
  (*((size_t *) ((char *) h - ALIGN(sizeof(size_t)))) & ~0x7)))

#define GET_HEADER(p) ((header *) ((char *) p - ALIGN(sizeof(header))))

#define GET_PAYLOAD(p) ((void *) ((char *) p + ALIGN(sizeof(header))))

#define NONE 0x0
#define ALLOCATED 0x1
#define ADJUST_ALLOCATED 0x2

#define IS_ALLOCATED(h) ((GET_ALLOC(h) & ALLOCATED) ? true : false)
#define IS_ADJUST_ALLOCATED(h) \
  ((GET_ALLOC(h) & ADJUST_ALLOCATED) ? true : false)

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

static void list_init(list *);
static list_elem * list_first(list *);
static void list_insert(list_elem *, list_elem *);
static void list_add(list *, list_elem *);
static list_elem * list_remove(list_elem *);
static bool list_empty(list *);
static bool list_compare(list_elem *, list_elem *);

/* private functions. */
static int size_to_index(size_t);
static void set_free_state(header *);
static header * get_fit_block(list *, size_t);
static header * split_block(header *, size_t);
static bool expand_heap(size_t);
static header * coalesce_block(header *);

/* array of free lists. */
static list * free_bin;

/* alloc list. */
static list alloc_list;

/* for debugging. */
static int debug_indent;
static int debug_count;
static bool debug_flag;

static void deb_print_indent(void)
{
  int i;
  for (i = 0; i < debug_indent; i++)
    printf(" | ");
}

static void deb(void)
{
  if (debug_flag)
  {
    deb_print_indent();
    printf(" Debug Point : (%d)\n", ++debug_count);
  }
}

static void prt(const char * str, long num)
{
  if (debug_flag)
  {
    deb_print_indent();
    printf(" %s : %ld\n", str, num);
  }
}

static void prtp(const char * str, void * ptr)
{
  if (debug_flag)
  {
    deb_print_indent();
    printf(" %s : %p\n", str, ptr);
  }
}

static void msg(const char * str)
{
  if (debug_flag)
  {
    deb_print_indent();
    printf(" %s : (%d)\n", str, ++debug_count);
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
  for (e = list_first(list); !list_is_tail(e); e = e->next)
    if (list_compare(elem, e))
      break;

  list_insert(e, elem);
}

static list_elem * list_remove(list_elem * elem)
{
  if (!list_is_body(elem))
    return NULL;

  elem->prev->next = elem->next;
  msg("elem->prev->next = elem->next");
  elem->next->prev = elem->prev;
  msg("elem->next->prev = elem->prev");
  return elem->next;
}

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

static void list_print(list * list)
{
  list_elem * e;
  for (e = &list->head; ; e = e->next)
    if (list_is_head(e))
      printf("|h|");
    else if (list_is_body(e))
    {
      header * block = list_item(e, header, elem);
      printf( "-|%d: %p|", GET_SIZE(block), block);
    }
    else
    {
      printf("-|t|\n");
      break;
    }
}

static void bin_print(void)
{
  if (!debug_flag)
    return;

  deb_print_indent();
  printf(" print free bin[0~127]...\n");
  debug_indent++;

  int index;
  for (index = 0; index < BIN_SIZE; index++)
    if (!list_empty(&free_bin[index]))
    {
      deb_print_indent();
      printf(" bin[%d]:\t", index);
      list_print(&free_bin[index]);
    }
  debug_indent--;
}

static int size_to_index(size_t bytes)
{
  unsigned int words = (bytes - 1) / ALIGNMENT + 1;
  if (words <= 1)
    return 0;
  else if (words <= 64)
    return words - 2;
  else
  {
    int i = 1;
    for (words -= 64; 1<<(i+2) < words; i++) ;
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
  /* initialize free_bin of free lists and allocate space for dummy block. */
  size_t size
    = ALIGN(BIN_SIZE * sizeof(list))                  // bin[BIN_SIZE].
    + ALIGN(sizeof(header)) + ALIGN(sizeof(size_t))   // dummy head block.
    + ALIGN(sizeof(header));                          // dummy tail block.
  void * allocated_area = mem_sbrk(size);

  //debug_flag = true;
  debug_indent++;
  msg("<mm_init called>");

  if (allocated_area == (void *) -1)
    free_bin = NULL;
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
  *GET_FOOTER(dummy_head) = MIN_MALLOC | ALLOCATED;

  prtp("mm_init: dummy_head", dummy_head);

  header * dummy_tail
    = (header *) ((char *) allocated_area + size - ALIGN(sizeof(header)));
  dummy_tail->size = ALIGN(sizeof(size_t)) | ADJUST_ALLOCATED | ALLOCATED;

  prtp("mm_init: dummy_tail", dummy_tail);

  /* initialize alloc list. */
  list_init(&alloc_list);

  debug_indent--;
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

  debug_indent++;
  msg("<malloc called>");
  prt("malloc: payload", payload);

  /* set bytes for allocate, considering minimum value. */
  size_t bytes = ALIGN(sizeof(header)) + ALIGN(payload);
  if (bytes < MIN_MALLOC)
    bytes = MIN_MALLOC;

  prt("malloc: aligned bytes", bytes);

  /* search best fit block from small size class. */
  int index = size_to_index(bytes);
  while (true)
  {
    /* search best-fit free block. */
    if (!list_empty(&free_bin[index]))
    {
      prt("malloc: found non-empty free list, index", index);
      ret_block = get_fit_block(&free_bin[index], bytes);
      if (ret_block != NULL)
      {
        /* set allocate states. */
        ret_block->size |= ALLOCATED;
        GET_NEXT(ret_block)->size |= ADJUST_ALLOCATED;

        prt("malloc: found free block, index", index);
        bin_print();

        debug_indent--;
        return GET_PAYLOAD(ret_block);
      }
    }

    /* get more space when failed to allocate proper block. */
    if (++index == BIN_SIZE)
    {
      msg("malloc calls expand_heap");
      if (!expand_heap(bytes))
        return NULL;
      else
        index = size_to_index(bytes);
      msg("malloc: expand successed");
    }
  }
}

/*
 * get_fit_block - Search a best fit block by check all blocks in list
 *  and return it.
 */
static header * get_fit_block(list * list, size_t bytes)
{
  debug_indent++;
  list_elem * e = list_first(list);
  for (; !list_is_tail(e); e = e->next)
  {
    header * e_block = list_item(e, header, elem);

    /* check if e_block is big enough to match. */
    if (e_block->size >= bytes)
    {
      if (e_block->size < bytes + MIN_MALLOC)
      {
        prtp("malloc: calls list_remove, block", e_block);
        list_remove(e);
        list_add(&alloc_list, e);
      }
      else  // e_block->size >= bytes + MIN_MALLOC
      {
        msg("malloc calls split_block");
        e_block = split_block(e_block, bytes);
        list_add(&alloc_list, &e_block->elem);
        prtp("malloc: a block splited out, pointer", e_block);
      }
      debug_indent--;
      return e_block;
    }
  }
  /* do not match at all. */
  debug_indent--;
  return NULL;
}

/*
 * split_block - Split a one block to two adjust blocks.
 *  Return a pointer to header of second block.
 */
static header * split_block(header * block, size_t bytes)
{
  debug_indent++;
  prt("malloc: original block size", GET_SIZE(block));
  prt("malloc: original block alloc", GET_ALLOC(block));
  if (false)  // FIXME
  {
    deb();
    header * prev = GET_PREV(block);
    prtp("Got prev", prev);

    prt("prev_block size", GET_SIZE(prev));
    prt("prev_block alloc", GET_ALLOC(prev));
    header * next = GET_NEXT(block);
    prt("next_block size", GET_SIZE(next));
    prt("next_block alloc", GET_ALLOC(next));
  }
  prt(">> block->size", block->size);
  prt(">> bytes", bytes);
  /* handle first block which remains in the free list. */
  block->size -= bytes;
  *GET_FOOTER(block) = GET_SIZE(block);

  prt(">> block->size revised", block->size);

  prt("malloc: splited block 1 size", GET_SIZE(block));
  prt("malloc: splited block 1 alloc", GET_ALLOC(block));

  prtp("malloc: calls list_remove, block", block);
  list_remove(&block->elem);
  list_add(&alloc_list, &block->elem);
  msg("malloc: block added to alloc_list (for free)");
  /*
  deb_print_indent();
  printf(" alloc_list: ");
  list_print(&alloc_list);
  */

  if (false)  // FIXME
  {
    deb();
    header * prev = GET_PREV(block);
    prtp("Got prev", prev);

    prt("prev_block size", GET_SIZE(prev));
    prt("prev_block alloc", GET_ALLOC(prev));
    header * next = GET_NEXT(block);
    prt("next_block size", GET_SIZE(next));
    prt("next_block alloc", GET_ALLOC(next));
  }

  /* handle second block which allocated to user. */
  block = GET_NEXT(block);
  block->size = bytes | ALLOCATED;
  *GET_FOOTER(block) = block->size;

  prt("malloc: splited block 2 size", GET_SIZE(block));
  prt("malloc: splited block 2 alloc", GET_ALLOC(block));
  prtp("malloc: calls free, block 1", GET_PREV(block));
  /* rearrange first block. */
  mm_free(GET_PAYLOAD(GET_PREV(block)));

  /* set allocated status of the next block. */
  GET_NEXT(block)->size |= ADJUST_ALLOCATED;

  debug_indent--;
  return block;
}

static bool expand_heap(size_t bytes)
{
  debug_indent++;
  /* make bytes aligned and larger than or equal to minimum value. */
  bytes = ALIGN(bytes);
  if (bytes < ALIGN(MIN_HEAP_INC))
    bytes = ALIGN(MIN_HEAP_INC);

  prt("expand: aligned bytes", bytes);

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
    *GET_FOOTER(area) = bytes;

    prtp("expand: pointer to heap chunk", area);
    prt("expand: alloc to heap chunk", GET_ALLOC(area));

    /* set dummy tail block. */
    GET_NEXT(area)->size = ALIGN(sizeof(header)) | ALLOCATED;

    msg("expand: calls free");

    list_add(&alloc_list, &area->elem);
    mm_free(ptr);

    msg("expand: free done");
    debug_indent--;

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

  debug_indent++;
  msg("<free called>");
  prtp("free: pointer to free_block", free_block);
  prt("free: size of free_block", GET_SIZE(free_block));
  prt("free: alloc_state - free_block", GET_ALLOC(free_block));
  prt("free: alloc_state - next_block", GET_ALLOC(GET_NEXT(free_block)));

  /* remove from alloc list. */
  prtp("free: calls list_remove, block", free_block);
  if (false) // FIXME
  {
    debug_indent++;
    deb();
    header * next = GET_NEXT(free_block);
    prtp("Got next", next);
    prt("next_block size", GET_SIZE(next));
    prt("next_block alloc", GET_ALLOC(next));

    header * prev = GET_PREV(free_block);
    prtp("Got prev", prev);
    prt("prev_block size", GET_SIZE(prev));
    prt("prev_block alloc", GET_ALLOC(prev));
    debug_indent--;
  }
  if (list_remove(&free_block->elem) == NULL)
    return;

  msg("free calls coalesce_block");
  /* set free and coalescing blocks. */
  set_free_state(free_block);
  free_block = coalesce_block(free_block);
  msg("free: coalesce over");
  prt("free: size of free_block", GET_SIZE(free_block));
  prt("free: state of free_block", GET_ALLOC(free_block));

  /* add to free list. */
  int index = size_to_index(GET_SIZE(free_block));
  list_add(&free_bin[index], &free_block->elem);
  prt("free: rearranged block to bin[index], index", index);
  prt("free: state of arranged free_block", GET_ALLOC(free_block));

  bin_print();
  debug_indent--;
}

static header * coalesce_block(header * block)
{
  debug_indent++;
  header * merged_block = block;

  /* merge with previous block. */
  if (!IS_ADJUST_ALLOCATED(block))
  {
    /* retreive previous block. */
    merged_block = GET_PREV(block);
    list_remove(&merged_block->elem);

    /* merge blocks. */
    merged_block->size += block->size;
    *GET_FOOTER(block) = GET_SIZE(merged_block);

    msg("coalesce: merge prev");
  }

  /* merge with next block. */
  if (!IS_ALLOCATED(GET_NEXT(merged_block)))
  {
    /* retreive next block. */
    block = GET_NEXT(block);
    list_remove(&block->elem);

    /* merge blocks. */
    merged_block->size += GET_SIZE(block);
    *GET_FOOTER(block) = GET_SIZE(merged_block);

    msg("coalesce: merge next");
  }

  debug_indent--;
  return merged_block;
}

/*
 * mm_realloc - empty implementation; YOU DO NOT NEED TO IMPLEMENT THIS
 */
void * mm_realloc(void * ptr, size_t t)
{
  list_print(&alloc_list);
  return ptr;
}

/*
 * mm_exit - finalize the malloc package.
 */
void mm_exit(void)
{
  debug_indent++;
  msg("<mm_exit called>");

  list_elem * e = list_first(&alloc_list);
  while (!list_is_tail(e))
  {
    e = e->next;
    header * block = list_item(e->prev, header, elem);
    mm_free(GET_PAYLOAD(block));
  }
  msg("mm_exit done");
  debug_indent--;
}
