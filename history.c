#include "monitoring.h"

#define HISTORY_MAX	10

extern FILE*		log_file;

static char*		history_key[HISTORY_MAX];
static int		history_pos[HISTORY_MAX];

static int		history_count		= 0;

int history_getpos(const char* key) {
  int		i;

  for(i=0;i<history_count;i++) {
    if(strcmp(history_key[i],key) == 0) {
      return(history_pos[i]);
    }
  }
  return(0);
}

void history_setpos(const char* key,int pos) {
  int		i;

  for(i=0;i<history_count;i++) {
    if(strcmp(history_key[i],key) == 0) {
      history_pos[i] = pos;
      return;
    }
  }

  assert(history_count < HISTORY_MAX);
  history_key[history_count] = strdup(key);
  history_pos[history_count] = pos;
  history_count++;
}

void history_seek(FILE* datafile,const char* key) {
  int		startpos;

  startpos = history_getpos(key);
  if(startpos > 0) {
    struct stat         finfo;
    int			result;
		
    result = fstat(fileno(datafile),&finfo);
    if(result == 0 && finfo.st_size >= startpos) {
      fseek(datafile,startpos,SEEK_SET);
      fprintf(log_file,"... skipping to log location %d\n",startpos);
    }
  }
}

void history_load() {
  FILE*		history_file;
  char		entry[128];

  history_file = fopen(CONFIG_HISTORYFILE,"r");
  if(!history_file)
    return;

  while(fgets(entry,sizeof(entry),history_file)) {
    char**	fields;

    fields = strsplita(entry,"=",2);
    history_setpos(fields[0],atoi(fields[1]));
    freesplit(fields,2);
  }
}

void history_save() {
  FILE*		history_file;
  int		i;

  history_file = fopen(CONFIG_HISTORYFILE,"w");
  assert(history_file);

  for(i=0;i<history_count;i++) {
    fprintf(history_file,"%s=%d\n",history_key[i],history_pos[i]);
    free(history_key[i]);
  }
  fclose(history_file);
}

