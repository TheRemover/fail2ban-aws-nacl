"""This script is used to block and unblock IPs on Amazon EC2
network ACLs and can be used with Fail2Ban. Since only 20
inbound rules are allowed with AWS if a 'jail' is provided
the IP will be blocked on the host iptables if full"""

import json
import sqlite3
import argparse
import os
import pprint
import socket
import logging
import logging.handlers
import requests
import boto3
import subprocess

#Constants
#AWS only allows 20 inbound subtract default ACL rules from 20 for max
MAX_BLOCKS = 10
#Set range for rules
RULE_RANGE = 100
#Set rule start, by default AWS ACL starts rules at 100
RULE_BASE = 1

def print_acl(acl):
    """This function prints the ACL given an ec2 object and ACL id"""
    ec2 = boto3.client('ec2')
    acl_response = ec2.describe_network_acls(
        NetworkAclIds=[
            acl,
        ],
    )
    pretty_printer = pprint.PrettyPrinter(indent=4)
    pretty_printer.pprint(acl_response['NetworkAcls'][0]['Entries'])

def is_acl(acl):
    ec2 = boto3.client('ec2')
    try:
        ec2.describe_network_acls(
            NetworkAclIds=[
                acl,
            ],
        )
        return True
    except Exception:
        return False

def get_acl():
    ec2 = boto3.client('ec2')
    meta = "http://169.254.169.254/latest/meta-data/network/interfaces/macs/"
    mac = requests.get(meta).text
    subnet = requests.get(meta+mac+"/subnet-id").text

    response = ec2.describe_network_acls(
        Filters=[
            {
                'Name': 'association.subnet-id',
                'Values':[
                    subnet
                ]
            },
        ],
        DryRun=False
    )
    return response['NetworkAcls'][0]['Associations'][0]['NetworkAclId']

def validate_ip(ip_address):
    ip_split = ip_address.split('.')
    if len(ip_split) != 4:
        return False
    for octet in ip_split:
        if not octet.isdigit():
            return False
        octet_int = int(octet)
        if octet_int < 0 or octet_int > 255:
            return False
    try:
        socket.inet_aton(ip_address)
        return True
    except socket.error:
        return False

def sqlite_connect(file_name):
    make_table = '''CREATE TABLE if not exists blocks (id integer PRIMARY KEY AUTOINCREMENT,
               ip text NOT NULL, acl text NOT NULL, blocked boolean NOT NULL,host boolean
               NOT NULL)'''
    if not os.path.isfile(file_name):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        conn = sqlite3.connect("{}/{}".format(dir_path, file_name))
        cursor = conn.cursor()
        cursor.execute(make_table)
        conn.commit()
    else:
        try:
            conn = sqlite3.connect(file_name)
            cursor = conn.cursor()
            cursor.execute(make_table)
            conn.commit()
        except Exception:
            print "Datatbase File is encrypted or is not a database"
            exit(1)
    return conn


def main():
    logging.basicConfig(level=logging.ERROR)
    my_logger = logging.getLogger(__file__)
    my_logger.info('Checking arguments')
    parser = argparse.ArgumentParser(description="Script to block IPs on AWS EC2 Network ACL")
    parser.add_argument('-a', '--acl', help='ACL ID')
    parser.add_argument('-i', '--ip', help='IP address')
    parser.add_argument('-j', '--jail', help='Fail2Ban Jail')
    parser.add_argument('-d', '--db', default='aws-nacl.db', help='Database')
    parser.add_argument('-b', '--block', action='store_true', help='Block IP address')
    parser.add_argument('-u', '--unblock', action='store_true', help='Unblock IP address')
    parser.add_argument('-g', '--get', action='store_true', help='Get ACL')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    args = parser.parse_args()

    ec2_resource = boto3.resource('ec2')

    if args.verbose:
        my_logger.info('Setting logging to debug')
        my_logger.setLevel(logging.DEBUG)

    if (args.block and args.unblock) or (not args.ip and (args.unblock or args.block)):
        my_logger.error('Invalid arguments')
        parser.print_usage()
        exit(1)

    if args.acl:
        my_logger.info('Checking if valid AWS Network ACL')
        if not is_acl(args.acl):
            print('Invalid Network ACL ID')
            my_logger.error('Invalid Network ACL')
            exit(1)
    else:
        my_logger.info('Searching for current ACL ID')
        acl = get_acl()
        network_acl = ec2_resource.NetworkAcl(acl)
        my_logger.debug('Network ACL ID: {}'.format(network_acl))

    if args.get or (not args.block and not args.unblock):
        my_logger.info('Printing ACL')
        print_acl(acl)
        exit(0)


    my_logger.info('Configuring DB')
    conn = sqlite_connect(args.db)
    cursor = conn.cursor()

    if args.block:
        my_logger.info('Checking if valid IP')
        if not validate_ip(args.ip):
            print "IP {} is invalid".format(args.ip)
            exit(1)
        my_logger.info('Searching DB for IP: {}'.format(args.ip))
        cursor.execute('''select count (*) from blocks where ip=? and blocked=1''', (args.ip,))
        if cursor.fetchone()[0] > 0:
            print "IP {} already blocked".format(args.ip)
            exit(0)
        my_logger.info('Checking AWS block count')
        cursor.execute('''select count (*) from blocks where blocked=1 and host =0''')
        block_count = cursor.fetchone()[0]
        my_logger.debug('Currently {} IPs blocked'.format(block_count))
        if block_count <= MAX_BLOCKS:
            my_logger.debug('Current blocks less then Max: {}'.format(MAX_BLOCKS))
            my_logger.info('Adding block to the DB')
            cursor.execute('''insert into blocks (ip, acl, blocked,host)
                               values (?,?,?,?)''', (args.ip, acl, 1, 0))
            conn.commit()
            my_logger.info('Caculating Rule number based on DB ID')
            cursor.execute('''select seq from sqlite_sequence where name="blocks"''')
            rule_num = cursor.fetchone()[0] % RULE_RANGE + RULE_BASE
            my_logger.info('Adding Network ACL')
            network_acl.create_entry(
                CidrBlock=args.ip+'/32',
                DryRun=False,
                Egress=False,
                PortRange={
                    'From': 0,
                    'To': 65535
                },
                Protocol='-1',
                RuleAction='deny',
                RuleNumber=rule_num
            )
        else:
            my_logger.debug('Max blocks on AWS Network ACL, checking for IPTables') 
            if  args.jail:
                my_logger.info('Blocking IP {} in f2b-{}'.format(args.ip,args.jail))
                iptables = "/sbin/iptables -w -I {} 1 -s {} -j REJECT".format(args.jail, args.ip)
                print iptables
                subprocess.call(iptables, shell=True)
                cursor.execute('''insert into blocks (ip, acl, blocked,host)
                                  values (?,?,?,?)''', (args.ip, '', 1, 1))
                conn.commit()
            else:
                my_logger.error('No IPtables Chain set, IP will not be blocked')
    if args.unblock:
        my_logger.info('Checking if valid IP')
        if not validate_ip(args.ip):
            my_logger.error("IP {} is invalid".format(args.ip))
            exit(1)
        my_logger.info('Checking for IP in the DB')
        test = 'select id, host from blocks where ip="{}" and blocked=1'.format(args.ip)
        cursor.execute(test)
        results = cursor.fetchone()
        if results is not None:
            my_logger.info('Found IP, getting rule number from DB')
            if results[1] == 0:
                rule_num = results[0] % RULE_RANGE + RULE_BASE
                my_logger.debug('Rule number is {}'.format(rule_num))
                my_logger.info('Deleting rule from AWS Network ACL')
                response = network_acl.delete_entry(
                    DryRun=False,
                    Egress=False,
                    RuleNumber=rule_num
                )
                my_logger.info('Updating DB')
                cursor.execute('''UPDATE blocks SET blocked = 0 where ip=? and
                                   blocked=1''', (args.ip,))
                conn.commit()
            else:
                if args.jail:
                    my_logger.info('Unblocking IP {} in f2b-{}'.format(args.ip,args.jail))
                    iptables = 'iptables -w -D {} -s {} -j REJECT'.format(args.jail, args.ip)
                    subprocess.call(iptables, shell=True)
                    cursor.execute('''UPDATE blocks SET blocked = 0 where ip=? and blocked=1''', (args.ip,))
                    conn.commit()
        else:
            my_logger.error("IP {} not in blocks database".format(args.ip))
            exit(1)


if __name__ == "__main__":
    main()
