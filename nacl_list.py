import boto3
import socket
from tabulate import tabulate
import sys

def get_regions():
    """Function that retrieves the list of AWS regions

    Returns:
        array: List of AWS regions.

    """
    regions = []
    ec2 = boto3.client('ec2')
    response = ec2.describe_regions()
    for region in response["Regions"]:
        regions.append(region["RegionName"]) 
    return regions

def ip_search(ip, regions):
    """This function searches the list of AWS regions for the given private IP address

    Args:
        ip (str): Private IP address
        regions (array): List of AWS regions.

    Returns:
        array: List of instances 

    """
    instances = []
    for region in regions:
        ec2 = boto3.client('ec2',region_name=region)
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
                    instances.append({"id":instance["InstanceId"],"region":region,"acl":acl_id,"vpc":instance["VpcId"],"subnet":instance["SubnetId"],"public":instance["PublicIpAddress"]})
    return instances


def get_acl_id(vpc):
    """This functiion returns the ACL ID for the given VPC ID using the boto describe_network_acl  with a VPC filter

    Args:
        vpc (str): VPC ID

    Returns:
        str: ACL ID 

    """
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

def get_acl(acl_id):
    """This function returns the ACL JSON string using the boto describe_network_acls with the ACL_ID filter

    Args:
        acl_id (str): ACL ID
        regions (array): List of AWS regions.

    Returns:
        str: JSONG string of ACL

    """
    ec2 = boto3.client('ec2')
    acl_response = ec2.describe_network_acls(
        NetworkAclIds=[
            acl_id,
        ],
    )
    return acl_response

def print_inbound_acl(acl_id):
    """This function calls get_acl for the current ACL JSON and prints the results in a table using tabulate

    Args:
        acl_id (str): ACL ID

    """
    blocks = []
    table = {num:name[8:] for name,num in vars(socket).items() if name.startswith("IPPROTO")}
    acl = get_acl(acl_id)
    list = acl['NetworkAcls'][0]['Entries']
    for entry in list:
        if not entry["Egress"]:
            if "PortRange" in entry:
                ports = ({"To":entry["PortRange"]["To"], "From":entry["PortRange"]["From"]})
            else:
                ports = ({"To":"", "From":""})
            if entry['Protocol'] == "-1":
                proto = "all"
            else:
                proto = table[int (entry['Protocol'])]
            blocks.append([entry['RuleNumber'],proto,entry['CidrBlock'],ports["To"],ports["From"],entry['RuleAction']])
    print "Inbound Network ACL"
    print tabulate(blocks,headers=["Rule","Protocol","CIDR","Port From","Port To","Action"])

def validate_ip(ip_address):
    """This function checks if the given IP address is valid by checking for 4 octets and then using socket to validate

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
        print ("No IP address supplied: Usage: {} 0.0.0.0".format(sys.argv[0]))
        exit(1)
    if validate_ip(sys.argv[1]):
        instances = ip_search(sys.argv[1],get_regions())
        for instance in instances:
            print "Instance ID: {}\nPublic IP: {}\nRegion: {}\nSubnet: {}\nACL ID: {}".format(instance["id"],instance["public"],instance["region"],instance["subnet"],instance["acl"])
            print_inbound_acl(instance["acl"])

if __name__ == "__main__":
    main()
