#!/bin/python3

import boto3
from pprint import pprint

PERMITTED_PORTS = [80, 443]
REPLACE_IP = '127.0.0.1/32'
ALL_IP = '0.0.0.0'
ALL_NET = '/0'


def correct_rule(security_group, bad_rule, ingress=False):
    print('=== Bad rule detected ...')
    print(bad_rule)
    good_rule = bad_rule.copy()
    good_rule['IpRanges'] = [{'CidrIp': REPLACE_IP}]

    print('Correcting rule:', good_rule)
    if ingress:
        security_group.revoke_ingress(IpPermissions=[bad_rule])
        security_group.authorize_ingress(IpPermissions=[good_rule])
    else:
        security_group.revoke_egress(IpPermissions=[bad_rule])
        security_group.authorize_egress(IpPermissions=[good_rule])
    print('Done ===')


def correct_security_groups(client, ec2):
    # get the security groups
    security_groups = client.describe_security_groups()
    security_groups = security_groups['SecurityGroups']
    for sg in security_groups:
        group_id = sg['GroupId']
        group_name = sg['GroupName']
        # filter out security groups that are not default
        if 'default' not in group_name.lower():
            continue
        print('SecurityGroup:')
        pprint(sg)

        security_group = ec2.SecurityGroup(group_id)

        ip_perm_ingress = sg['IpPermissions']
        ip_perm_egress = sg['IpPermissionsEgress']
        for rule in ip_perm_ingress:
            bad_rules = [rule for ip_range in rule['IpRanges'] if ALL_IP in ip_range['CidrIp']]
            for bad_rule in bad_rules:
                correct_rule(security_group, bad_rule, ingress=True)
        for rule in ip_perm_egress:
            bad_rules = [rule for ip_range in rule['IpRanges'] if ALL_IP in ip_range['CidrIp']]
            for bad_rule in bad_rules:
                correct_rule(security_group, bad_rule, ingress=False)


def worker(region):
    print('== Working on region:', region)
    print('Getting resources ...')
    client = boto3.client('ec2', region_name=region)
    ec2 = boto3.resource('ec2', region_name=region)
    correct_security_groups(client, ec2)
    print('Done ==')
    print('='*75)


if __name__ == '__main__':
    print('Creating session ...')
    boto3.setup_default_session(profile_name='rcp')
    session = boto3.Session()
    print('Session:', session)
    regions = session.get_available_regions('ec2')
    pprint(regions)
    for region in regions:
        worker(region)


