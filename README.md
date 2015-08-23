# Apache Auto-Blacklist Monitor

This is a custom monitor which was developed in the hardening of a specific server but can easily be adopted to other enviornments

This monitor was run on a Hostgator CentOS VPS with cPanel 11.50, Apache 2.2, and mod_qos

This monitor reads data from:

* Standard Apache error log at: /usr/local/apache/logs/error_log
* mod_qs custom log at: /usr/local/apache/logs/qsaudit_log

This monitor is intended to interact with the Hostgator firewall, which has a global block file at /etc/firewall/GLOBAL_DROP and requires the firewall service to be restarted after modifications to the blocklist. It shoudl be easily adaptable to other firewalls.

This monitor maintains a few files at /var/log to keep track of IP addresses and log locations

## Custom mod_qos log

This monitor relies on mod_qos logging. Note that mod_qos may have to be added to Apache as it is not a default module

The custom log rule for mod_qos is:

```
<IfModule mod_qos.c>
  CustomLog             logs/qsaudit_log  "%t %h %>s %{mod_qos_cr}e %{mod_qos_ev}e %{QS_Block_Counter}e %{mod_qos_con}e %{QS_IPConn}e %{QS_SrvConn}e %{ms}T %v %{qos-loc}n %{qos-path}n %{qos-query}n id=%{UNIQUE_ID}e %{QS_ConnectionId}e"
</IfModule>
```

Please see the pre_virtualhost_global.conf for the specific mod_qos rules that were in place for this monitor.

## Building

To build this monitor simple use the included Makefile

After a successful build, add a crontab entry to call this monitor every 5 minutes

The monitor can be tested from the commandline by adding one ore more of the following commands

* test - run in test mode, does not modify files nor execute blacklist commands
* all  - ignores the history location and re-reads the entire file

