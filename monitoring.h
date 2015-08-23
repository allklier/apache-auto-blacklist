#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define _XOPEN_SOURCE 500
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <regex.h>
#include <assert.h>

#define max(a,b)        ((a > b)? a : b)

#define CONFIG_LOGFILE		 	"/var/log/modsec_mon_log"
#define CONFIG_HISTORYFILE		"/var/log/modsec_mon_history"
#define CONFIG_IPCACHEFILE		"/var/log/modsec_mon_ipcache"

typedef struct cache_entry {
  char          ipaddr[20];
  int           count;
  int           blocked;
} cache_entry_t;

int             ipcache_incr(const char* ipaddr);
void		ipcache_block(const char* ipaddr);
void            ipcache_load();
void            ipcache_save();

int		history_getpos(const char* key);
void		history_setpos(const char* key,int pos);
void		history_seek(FILE* datafile,const char* key);

void		history_load();
void		history_save();

int             regmatch(const regmatch_t* matchdata,const char* str,char** matches,int maxmatch);
void            regfreematch(char** matches,int maxmatch);
int 		strsplit(const char* str,const char* delim,char** fields,int maxfields,int maxcopy);
char** 		strsplita(const char* str,const char* delim,int max);
void 		freesplit(char** tokens,int max);

