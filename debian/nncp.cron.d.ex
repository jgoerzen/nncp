#
# Regular cron jobs for the nncp package
#
0 4	* * *	root	[ -x /usr/bin/nncp_maintenance ] && /usr/bin/nncp_maintenance
