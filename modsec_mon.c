#include "monitoring.h"

FILE*			log_file			= NULL;
time_t			now;

static const char* 	config_datafile_err 		= "/usr/local/apache/logs/error_log";
static const char*	config_datafile_qos		= "/usr/local/apache/logs/qsaudit_log";
static int		config_threshold_blacklist_err	= 100;
static int		config_threshold_blacklist_qos	= 500;

static const char*	config_whitelist[]		= { "216.172.180.191", "72.89.126.205" };

static int   		test_mode 			= 0;
static int   		all_data			= 0;

static int		blacklist_count			= 0;
static int		enforce_mode			= 1;

static void 		scan_error_log();
static void		scan_qos_log();
static void 		blacklist_ip(const char* ipaddr);

static time_t 		parse_timestamp(const char* timestring);

int main(int argc, char** argv) {
  int 	i;
  for(i=1;i<argc;i++) {
    if(strcmp(argv[i],"test") == 0)
      test_mode = 1;
    if(strcmp(argv[i],"all") == 0)
      all_data = 1;
  } 
  
  now = time(NULL);
  log_file = fopen(CONFIG_LOGFILE,"a+");
  fprintf(log_file,"started at %s",ctime(&now));

  if(!all_data) {
    ipcache_load();
    history_load();
  }
  else 
    fprintf(log_file,"not loading cache due to all data\n");

  scan_error_log();
  scan_qos_log();

  if(!test_mode) {
    ipcache_save();
    history_save();
  }

  if(!test_mode && enforce_mode && blacklist_count > 0) {
    fflush(stdout);
    system("/sbin/service firewall restart");
    
    fprintf(log_file,"restarted firewall due to %d new blacklist entries\n",blacklist_count);
  }

  fclose(log_file);

  return 0;
}

static void scan_error_log() {
  FILE* 	data_file;
  char 		entry[1024];

  const char*  	timestamp_r	 	= "^\\[([[:alnum:][:space:]:]*)\\]";
  regex_t       timestamp_rc;
  regmatch_t	timestamp_m[2];
  char*		timestamp_str[2];

  const char*	client_r		= "\\[client [i]?[p]?[ ]?([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\]";
  regex_t	client_rc;
  const char*	client_r2		= "c=([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})";
  regex_t	client_rc2;
  regmatch_t	client_m[2];
  char*		client_str[2];

  int		count			= 0;
  int		status;

  fprintf(log_file,"... scanning errorlog\n");

  // compile regexs
  status = regcomp(&timestamp_rc,timestamp_r,REG_EXTENDED);  
  if(status) {
    char	errortext[128] = "";

    regerror(status,&timestamp_rc,errortext,sizeof(errortext));
    printf("error compiling regex: %s (%s)\n",errortext,timestamp_r);
    exit(1);
  }
  status = regcomp(&client_rc,client_r,REG_EXTENDED);  
  if(status) {
    char	errortext[128] = "";

    regerror(status,&client_rc,errortext,sizeof(errortext));
    printf("error compiling regex: %s (%s)\n",errortext,client_r);
    exit(1);
  }
  status = regcomp(&client_rc2,client_r2,REG_EXTENDED);  
  if(status) {
    char	errortext[128] = "";

    regerror(status,&client_rc2,errortext,sizeof(errortext));
    printf("error compiling regex: %s (%s)\n",errortext,client_r2);
    exit(1);
  }
  
  data_file = fopen(config_datafile_err,"r");
  if(!data_file) {
    printf("unable to open data file\n");
    exit(1);
  }
  if(!all_data)
    history_seek(data_file,"errorlog");
  else
    fprintf(log_file,"forcing all data to be read\n");

  while(fgets(entry,sizeof(entry),data_file)) {
    time_t	logtime;

    status = regexec(&timestamp_rc,entry,2,timestamp_m,0);
    if(status == REG_NOMATCH) {
      printf("unable to find timestamp via regex: '%s'\n",entry);
      printf("regex was: '%s'\n",timestamp_r);
      break;
    }
    regmatch(timestamp_m,entry,timestamp_str,2);
    logtime = parse_timestamp(timestamp_str[1]);

    if(all_data == 1 || now - logtime <= 300){
      int	pattern		= 0;
      int	new_count;
      int	matches;

      // Look for signatures
      // - 'ModSecurity' and 'Access denied with code'
      if(strstr(entry,"ModSecurity") && strstr(entry,"Access denied with code"))
	pattern = 1;
      // - QoS & Client Event
      if(strstr(entry,"mod_qos") && strstr(entry,"QS_ClientEventBlockCount"))
	pattern = 1;
      // - QoS & LogRequestLimit
      if(strstr(entry,"mod_qos") && strstr(entry,"QS_LocRequestLimit"))
	pattern = 1;
      if(!pattern)
	continue;

      // Find client IP address
      status = regexec(&client_rc,entry,2,client_m,0);
      if(status == REG_NOMATCH) {
        status = regexec(&client_rc2,entry,2,client_m,0);
        if(status == REG_NOMATCH) {
          continue;
        }
      }
      matches = regmatch(client_m,entry,client_str,2);
      
      // Add to IP address map and block if threshold is reached
      new_count = ipcache_incr(client_str[matches-1]);
      if(new_count == config_threshold_blacklist_err) {
        // Check IP against whitelist
        int	wl_count = sizeof(config_whitelist) / sizeof(config_whitelist[0]);
        int	i;

        for(i=0;i<wl_count;i++) {
          fprintf(log_file,"Whitelist IP: %s\n",config_whitelist[i]);
          if(strcmp(config_whitelist[i],client_str[matches-1]) == 0) 
	    break;
        }
        if(i<wl_count) {
          fprintf(log_file,"Skipping IP due to whitelist\n");
          continue;
        }
	blacklist_ip(client_str[matches-1]);
      }
      
      regfreematch(client_str,2);

      count++;
    }
    
    regfreematch(timestamp_str,2);
  }

  fprintf(log_file,"... processed %d error log entries\n",count);

  if(!test_mode)
    history_setpos("errorlog",ftell(data_file));

  regfree(&timestamp_rc);
  regfree(&client_rc);
  fclose(data_file);
}

static void scan_qos_log() {
  FILE* 	data_file;
  FILE*		history_file;
  char 		entry[1024];

  int		count 		= 0;
  int		status;

  fprintf(log_file,"... scanning qos log\n");

  data_file = fopen(config_datafile_qos,"r");
  if(!data_file) {
    printf("unable to open data file\n");
    exit(1);
  }
  if(!all_data) 
    history_seek(data_file,"qoslog");
  else 
    fprintf(log_file,"forcing all data to be read\n");

  while(fgets(entry,sizeof(entry),data_file)) {
    char**	tokens;
    char	timestring[128];
    struct tm	t;
    time_t	logtime;
    int		new_count;

    tokens = strsplita(entry," ",15);

    strptime(tokens[0],"[%d/%b/%Y/%T",&t);
    logtime = mktime(&t);

    if(all_data == 1 || now - logtime <= 300){
      // must be status 509 and access denied status
      if(strcmp(tokens[3],"509") == 0 && strcmp(tokens[5],"D;") == 0 && strstr(tokens[13],"wp-login.php") != 0) {
        // Add to IP address map and block if threshold is reached
        new_count = ipcache_incr(tokens[2]);
        if(new_count == config_threshold_blacklist_qos) {
    	  blacklist_ip(tokens[2]);
        }

        count++;
      }      
    }
    
    freesplit(tokens,15);
  }

  fprintf(log_file,"... processed %d qos log entries\n",count);

  history_setpos("qoslog",ftell(data_file));

  fclose(data_file);
}

static void blacklist_ip(const char* ipaddr) {
  int		i;

  ipcache_block(ipaddr);
  blacklist_count++;
  fprintf(log_file,"blacklisting IP %s\n",ipaddr);
  printf("blacklisting %s\n",ipaddr);

  if(test_mode || !enforce_mode) {
    fprintf(log_file,"Not taking action due to test  mode\n");
    return;
  }

  if(enforce_mode != 0) {
    FILE*	blacklist_file;

    blacklist_file = fopen("/etc/firewall/GLOBAL_DROP","a+");
    if(!blacklist_file) {
      printf("unable to open blacklist file, skipping enforcement\n");
      return;
    }
    fprintf(blacklist_file,"%s\n",ipaddr);
    fclose(blacklist_file);
  }
}

// read timestamp and eval if line applies
// [Thu Aug 06 13:12:01 2015]
static time_t parse_timestamp(const char* timestring) {
  struct tm	t;
  int 		status;
  char		t_wday[4], t_mon[4];

  static const char*	l_mon[]  = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

  status = sscanf(timestring,"%3s %3s %d %02d:%02d:%02d %04d",t_wday,t_mon,&t.tm_mday,&t.tm_hour,&t.tm_min,&t.tm_sec,&t.tm_year);
  t.tm_year -= 1900;
  for(t.tm_mon=0;t.tm_mon<12;t.tm_mon++) {
    if(strcmp(t_mon,l_mon[t.tm_mon]) == 0) 
      break;
  }
  return(mktime(&t));
}

