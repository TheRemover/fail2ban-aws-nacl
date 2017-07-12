""" This module contains methods necessary to print a Amazon Web Services
EC2 Network ACL given a private IP address. It will search through all
instances in all regions for the private IP and print the ACL for each
instance found with the provided credentials.

If ID and key is not provided then boto will first check environment
variables, then the aws config in the home directory

Example:

        $ python nacl_list.py 1.2.3.4

Todo:
    * Add function for public IP search
    * Add arguments for public or private
"""

import sys
import socket
import boto3
from tabulate import tabulate

def get_regions(aws_id=0, aws_key=0):
    """Function that retrieves the list of AWS regions. If ID and key is not provided then
       boto will first check environment variables, then the aws config in the home directory

    Args:
        aws_id (str): AWS accessKeyID
        aws_key (str): AWS secretAccessKey

    Returns:
        array: List of AWS regions.

    """
    regions = []
    if aws_id and aws_key:
        ec2 = boto3.client('ec2', aws_access_key_id=aws_id,
                           aws_secret_access_key=aws_key)
    else:
        ec2 = boto3.client('ec2')
    response = ec2.describe_regions()
    for region in response["Regions"]:
        regions.append(region["RegionName"])
    return regions

def ip_search(ip, regions, aws_id=0, aws_key=0):
    """This function searches the list of AWS regions for the given private IP address

    Args:
        ip (str): Private IP address
        regions (array): List of AWS regions.
        aws_id (str): AWS accessKeyID
        aws_key (str): AWS secretAccessKey

    Returns:
        array: List of instances

    """
    instances = []
    for region in regions:
        if aws_id and aws_key:
            ec2 = boto3.client('ec2', region_name=region, aws_access_key_id=aws_id,
                               aws_secret_access_key=aws_key)
        else:
            ec2 = boto3.client('ec2', region_name=region)
        response = ec2.describe_instances(
            Filters=[
                {
                    'Name': 'private-ip-address',
                    'Values': [
                        ip,
                    ]
                },
            ],
            DryRun=False
        )
        if response["Reservations"]:
            for reservation in response["Reservations"]:
                for instance in reservation["Instances"]:
                    acl_id = get_acl_id(instance["VpcId"])
                    instances.append({"id":instance["InstanceId"], "region":region, "acl":acl_id,
                                      "vpc":instance["VpcId"], "subnet":instance["SubnetId"],
                                      "public":instance["PublicIpAddress"]})
    return instances


def get_acl_id(vpc, aws_id=0, aws_key=0):
    """This functiion returns the ACL ID for the given VPC ID using the boto describe_network_acl
       with a VPC filter

    Args:
        vpc (str): VPC ID

    Returns:
        str: ACL ID
        aws_id (str): AWS accessKeyID
        aws_key (str): AWS secretAccessKey

    """
    if aws_id and aws_key:
        ec2 = boto3.client('ec2', aws_access_key_id=aws_id,
                           aws_secret_access_key=aws_key)
    else:
        ec2 = boto3.client('ec2')
    response = ec2.describe_network_acls(
        Filters=[
            {
                'Name': 'vpc-id',
                'Values':[
                    vpc
                ]
            },
        ],
        DryRun=False
    )
    return response['NetworkAcls'][0]['Associations'][0]['NetworkAclId']

def get_acl(acl_id, aws_id=0, aws_key=0):
    """This function returns the ACL JSON string using the boto describe_network_acls
       with the ACL_ID filter

    Args:
        acl_id (str): ACL ID
        regions (array): List of AWS regions.

    Returns:
        str: JSON string of ACL
        aws_id (str): AWS accessKeyID
        aws_key (str): AWS secretAccessKey

    """
    if aws_id and aws_key:
        ec2 = boto3.client('ec2', aws_access_key_id=aws_id,
                           aws_secret_access_key=aws_key)
    else:
        ec2 = boto3.client('ec2')
    acl_response = ec2.describe_network_acls(
        NetworkAclIds=[
            acl_id,
        ],
    )
    return acl_response

def print_inbound_acl(acl_id, aws_id=0, aws_key=0):
    """This function calls get_acl for the current ACL JSON and prints the results in a
       table using tabulate

    Args:
        acl_id (str): ACL ID
        aws_id (str): AWS accessKeyID
        aws_key (str): AWS secretAccessKey

    """
    blocks = []
    table = {num:name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}
    acl = get_acl(acl_id, aws_id, aws_key)
    acl_list = acl['NetworkAcls'][0]['Entries']
    for entry in acl_list:
        if not entry["Egress"]:
            if "PortRange" in entry:
                ports = ({"To":entry["PortRange"]["To"], "From":entry["PortRange"]["From"]})
            else:
                ports = ({"To":"", "From":""})
            if entry['Protocol'] == "-1":
                proto = "all"
            else:
                proto = table[int(entry['Protocol'])]
            blocks.append([entry['RuleNumber'], proto, entry['CidrBlock'], ports["To"],
                           ports["From"], entry['RuleAction']])
    print "Inbound Network ACL"
    print tabulate(blocks, headers=["Rule", "Protocol", "CIDR", "Port From", "Port To", "Action"])

def validate_ip(ip_address):
    """This function checks if the given IP address is valid by checking for 4 octets and then
       using socket to validate

    Args:
        ip (str): Private IP address

    Returns:
        boolean: Returns True if valid, False otherwise

    """
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

def main():
    if len(sys.argv) != 2:
        print "No IP address supplied: Usage: {} 0.0.0.0".format(sys.argv[0])
        exit(1)
    if validate_ip(sys.argv[1]):
        instances = ip_search(sys.argv[1], get_regions())
        for instance in instances:
            print "Instance ID: {}\nPublic IP: {}\nRegion: {}\nSubnet: {}\nACL ID: {}".format(
                instance["id"], instance["public"], instance["region"], instance["subnet"],
                instance["acl"])
            print_inbound_acl(instance["acl"])

if __name__ == "__main__":
    main()
