#include "monitoring.h"

extern int		test_mode;

extern FILE*		log_file;

static cache_entry_t*   ipcache                         = NULL;
static int              ipcache_count                   = 0;
static int              ipcache_allocated               = 0;

static void             ipcache_add(const char* ipaddr,int count,int blocked);

int ipcache_incr(const char* ipaddr) {
  int           i;

  for(i=0;i<ipcache_count;i++) {
    if(strcmp(ipcache[i].ipaddr,ipaddr) == 0) {
      ipcache[i].count++;
      return(ipcache[i].count);
    }
  }
  ipcache_add(ipaddr,1,0);
  return(1);
}

void ipcache_block(const char* ipaddr) {
  int           i;

  for(i=0;i<ipcache_count;i++) {
    if(strcmp(ipcache[i].ipaddr,ipaddr) == 0) {
      ipcache[i].blocked = 1;
      return;
    }
  }
  assert(0);
}

void ipcache_load() {
  FILE*                 cache_file;
  char                  entry[128];
  char                  ipaddr[20];
  int                   blocked;

  cache_file = fopen(CONFIG_IPCACHEFILE,"r");
  if(cache_file == NULL)
    return;

  while(fgets(entry,sizeof(entry),cache_file)) {
    char**	fields;

    fields = strsplita(entry,",",3);
    ipcache_add(fields[0],atoi(fields[1]),atoi(fields[2]));
    freesplit(fields,3);
  }
  fclose(cache_file);

  fprintf(log_file,"loaded ip cache with %d entries\n",ipcache_count);
}

void ipcache_save() {
  FILE*                 cache_file;
  cache_entry_t*        p_entry;
  int                   i;

  cache_file = fopen(CONFIG_IPCACHEFILE,"w+");
  assert(cache_file != NULL);

  p_entry = ipcache;
  for(i=0;i<ipcache_count;i++,p_entry++) {
    fprintf(cache_file,"%s,%d,%d\n",p_entry->ipaddr,p_entry->count,p_entry->blocked);
  }
  fclose(cache_file);
  if(ipcache)
    free(ipcache);

  fprintf(log_file,"saved ip cache with %d entries\n",ipcache_count);
}

static void ipcache_add(const char* ipaddr,int count,int block) {
  cache_entry_t*        p_entry;

  if(ipcache_count == ipcache_allocated) {
    cache_entry_t*      oldcache = ipcache;

    ipcache_allocated += 100;
    ipcache = malloc(ipcache_allocated * sizeof(cache_entry_t));
    assert(ipcache != NULL);

    if(oldcache != NULL) {
      memcpy(ipcache,oldcache,ipcache_count * sizeof(cache_entry_t));
      free(oldcache);
    }
  }

  p_entry = &ipcache[ipcache_count++];

  strncpy(p_entry->ipaddr,ipaddr,20);
  p_entry->count = count;
  p_entry->blocked = block;
}

