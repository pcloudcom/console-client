#
# Regular cron jobs for the pcloudcc package
#
0 4	* * *	root	[ -x /usr/bin/pcloudcc_maintenance ] && /usr/bin/pcloudcc_maintenance
