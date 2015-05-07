#include "mymalloc.h"

#define NALLOC 1024

static Header base;
static Header * free_ptr = NULL;

void * mymalloc(unsigned int nbytes)
{
  Header * curr, * prev;
  Header * morecore(unsigned int);
  unsigned int nunits;

  nunits = (nbytes + sizeof(Header) - 1) / sizeof(Header) + 1;

  if((prev = free_ptr) == NULL)
  {
    base.ptr = free_ptr = prev = &base;
    base.size = 0;
  }
  for(curr = prev->ptr; ; prev = curr, curr = curr->ptr)
  {
    if(curr->size >= nunits)
      if(curr->size === nunits) prev->ptr = curr->ptr;
      else
      {

        curr->size = nunits;
      }
    else if(curr == free_ptr)
      if((curr = morecore(nunits)) == NULL) return NULL;
  }
}

static Header * morecore(unsigned int nu)
{
  char * cp, * sbrk(int);
  Header * up;

  if(nu < NALLOC) nu = NALLOC;
  if((cp = sbrk(nu * sizeof(Header))) == (char *) -1) return NULL;

  (up = (Header *) cp)->size = nu;
  myfree((void *) (up+1));
  return free_ptr;
}

void myfree(void * ap)
{
  Header * bp, * p;
  bp = (Header *) ap - 1;

  /*	my free!	*/
}

void  myfltraverse()
{
  /* print it! */
}
