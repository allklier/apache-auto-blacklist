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

int strsplit(const char* str,const char* delimiter,char** fields,int maxfields,int maxcopy) {
  char*         workstring;
  int           fieldcount;
  int           i;

  workstring = strdup(str);

  fieldcount = 0;
  for(i=0;i<maxfields;i++,fieldcount++) {
    char* token = strtok((i == 0)?workstring : NULL,delimiter);
    if(!token) 
      break;

    strncpy(fields[i],token,maxcopy);
  }
  for(;i<maxfields;i++)
    fields[i] = NULL;

  free(workstring);
  return(fieldcount);
}

char** strsplita(const char* str,const char* delimiter,int max) {
  char**        result;
  char*         workstring;
  int           i;

  workstring = strdup(str);

  result = malloc(sizeof(char*) * max);
  assert(result != NULL);

  for(i=0;i<max;i++) {
    char* token = strtok((i == 0)?workstring : NULL,delimiter);
    if(!token) {
      break;
    }
    result[i] = strdup(token);
  }
  for(;i<max;i++)
    result[i] = NULL;

  free(workstring);
  return(result);
}

void freesplit(char** tokens,int size) {
  int i;

  for(i=0;i<size;i++) {
    if(tokens[i] != NULL) {
      free(tokens[i]);
    }
  }
  free(tokens);
}

int regmatch(const regmatch_t* matchdata,const char* str,char** matches,int maxmatch) {
  int   start;
  int   end;
  int   count;
  int   i,n;

  for(i=0;i<maxmatch;i++) {
    if(matchdata[i].rm_so == -1)
      break;

    n = matchdata[i].rm_eo - matchdata[i].rm_so;
    matches[i] = malloc(n + 1);
    strncpy(matches[i],str+matchdata[i].rm_so,n);
    matches[i][n] = 0;
  }
  count = i;
  for(;i<maxmatch;i++)
    matches[i] = NULL;

  return(count);
}

void regfreematch(char** matches,int maxmatch) {
  int   i;

  for(i=0;i<maxmatch;i++) {
    if(matches[i] != NULL)
      free(matches[i]);
  }
}



