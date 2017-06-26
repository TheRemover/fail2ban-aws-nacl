# fail2ban-aws-nacl
AWS Network ACL Fail2ban Script

This script is used as a standalone script to block and unblock IPs on Amazon EC2 network ACLs or can be used with Fail2Ban. Since only 20 inbound rules are allowed with AWS if an IPtables 'jail' is provided the IP will be blocked on the host iptables 
if necessary

This script uses a local sqlite database that will be created in the same directory as this script is run or one can be specified with the -d flag.

<pre>
usage: aws_nacl.py [-h] [-a ACL] [-i IP] [-j JAIL] [-d DB] [-b] [-u] [-g] [-v]

Script to block IPs on AWS EC2 Network ACL

optional arguments:
  -h, --help            show this help message and exit
  -a ACL, --acl ACL     ACL ID
  -i IP, --ip IP        IP address
  -j JAIL, --jail JAIL  Fail2Ban Jail
  -d DB, --db DB        Database
  -b, --block           Block IP address
  -u, --unblock         Unblock IP address
  -g, --get             Get ACL
  -v, --verbose         Verbose logging
  </pre>
  
  If used with Fail2Ban, aws.conf needs to be copied to the Fail2Ban action.d folder and jail.local needs to be copeid to the Fail2ban folder to set the default ban action. The location of the aws_nacl.py script will need to be specified for your use case in aws.conf.
  
  AWS User ID and Pass for awscli will need to be configured prior to first run. 
  
  
