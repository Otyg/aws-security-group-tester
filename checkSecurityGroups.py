import boto3
import json
import re
from netaddr import IPNetwork
from argparse import ArgumentParser
import sys

client = boto3.client('ec2')
instances = {}
security_groups = {}
check_running = True

def main():
    argument_parser = ArgumentParser(description='Verify AWS security group configuration for instances')
    argument_parser.add_argument('-v','--verbose', action='store_true', dest='verbose', default=False, help='Turn on verbose output')
    arguments = argument_parser.parse_args()
    set_instances_and_security_groups()
    with open('expected_rules.json') as expected_rules:
        rules = json.load(expected_rules)
    status = 0
    for rule in rules:
        allowed = 'Allow' if rule['IsAllowed'] else 'Deny'
        rule_ok = is_rule_ok(rule)
        if not rule_ok or arguments.verbose:
            print(allowed + " from " + rule['Source'] + " to " + rule['Destination'] + " " + rule[
                'ProtocolAndRange'] + str(rule_ok))
            status = 1
    sys.exit(status)

def set_instances_and_security_groups():
    instances_response = client.describe_instances()
    for instance in instances_response['Reservations']:
        id = instance['Instances'][0]['InstanceId']
        instance_security_groups_and_rules = set_security_groups_and_rules(instance['Instances'][0]['SecurityGroups'])
        if 'PrivateIpAddress' in instance['Instances'][0]:
            ip = instance['Instances'][0]['PrivateIpAddress']
        else:
            ip = None
        if 'Tags' in instance['Instances'][0]:
            name = \
            next((item for item in instance['Instances'][0]['Tags'] if item["Key"] == "Name"), {'Value': 'None'})[
                'Value']
            instances[id] = {'Id': id, 'Name': name, 'Ip': ip,
                             'SecurityGroups': instance_security_groups_and_rules['Group_Ids'],
                             'EffectiveIncoming': instance_security_groups_and_rules['in'],
                             'EffectiveOutgoing': instance_security_groups_and_rules['out']}


def set_security_groups_and_rules(instance_security_groups):
    instance_security_group_ids = []
    instance_effective_incoming_rules = {}
    instance_effective_outgoing_rules = {}
    for group in instance_security_groups:
        instance_security_group_ids.append(group['GroupId'])
        if group['GroupId'] not in security_groups and check_running:
            security_groups[group['GroupId']] = \
            client.describe_security_groups(GroupIds=[group['GroupId']])['SecurityGroups'][0]
        instance_effective_incoming_rules = derive_effective_rules(instance_effective_incoming_rules, group['GroupId'],
                                                                   'IpPermissions')
        instance_effective_outgoing_rules = derive_effective_rules(instance_effective_outgoing_rules, group['GroupId'],
                                                                   'IpPermissionsEgress')
    return {'Group_Ids': instance_security_group_ids, 'in': instance_effective_incoming_rules,
            'out': instance_effective_outgoing_rules}


def derive_effective_rules(effective_rules, group_id, field):
    for rule in security_groups[group_id][field]:
        if rule['IpProtocol'] not in effective_rules:
            effective_rules[rule['IpProtocol']] = {}
        if 'ToPort' in rule:
            ports = str(rule['FromPort']) + "-" + str(rule['ToPort'])
            if ports not in effective_rules[rule['IpProtocol']]:
                effective_rules[rule['IpProtocol']][ports] = {}
                effective_rules[rule['IpProtocol']][ports]['Ip'] = []
                effective_rules[rule['IpProtocol']][ports]['Sg'] = []
            for ip_range in rule['IpRanges']:
                effective_rules[rule['IpProtocol']][ports]['Ip'].append(ip_range['CidrIp'])
            for sg_group in rule['UserIdGroupPairs']:
                effective_rules[rule['IpProtocol']][ports]['Sg'].append(sg_group['GroupId'])
        else:
            effective_rules['icmp'] = {}
            effective_rules['icmp']['Ip'] = []
            effective_rules['icmp']['Sg'] = []
            for ip_range in rule['IpRanges']:
                effective_rules['icmp']['Ip'].append(ip_range['CidrIp'])
            for sg_group in rule['UserIdGroupPairs']:
                effective_rules['icmp']['Sg'].append(sg_group['GroupId'])
    return effective_rules


def is_rule_ok(rule):
    rule_ok = False
    src_id = get_instance_id(rule['Source'])
    dst_id = get_instance_id(rule['Destination'])
    protocol = rule['ProtocolAndRange'].split('/')[0]
    port_range = rule['ProtocolAndRange'].split('/')[1]
    allowed_out = get_allowed(src_id, 'EffectiveOutgoing', protocol, port_range)
    allowed_in = get_allowed(dst_id, 'EffectiveIncoming', protocol, port_range)

    if (is_allowed_by_security_group(allowed_out, src_id, allowed_in, dst_id) or is_allowed_by_ip(rule['Source'],
                                                                                                  allowed_in[
                                                                                                      'Ip']) or is_allowed_by_ip(
            rule['Destination'], allowed_out['Ip'])) == rule['IsAllowed']:
        rule_ok = True
    return rule_ok


def get_allowed(id, direction, protocol, port_range):
    allowed = {'Sg': [], 'Ip': []}
    if id is not None:
        if '0-65535' in instances[id][direction][protocol]:
            allowed['Sg'].extend(instances[id][direction][protocol]['0-65535']['Sg'])
            allowed['Ip'].extend(instances[id][direction][protocol]['0-65535']['Ip'])
        if port_range in instances[id][direction][protocol]:
            allowed['Sg'].extend(instances[id][direction][protocol][port_range]['Sg'])
            allowed['Ip'].extend(instances[id][direction][protocol][port_range]['Ip'])
    return allowed


def get_instance_id(label):
    pattern = re.compile("^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
    if pattern.match(label):
        return get_instance_id_from_ip(label)
    else:
        return get_instance_id_from_name(label)


def get_instance_id_from_name(name):
    for key in instances:
        if instances[key]['Name'] == name:
            return key
    return None


def get_instance_id_from_ip(ip):
    for key in instances:
        if instances[key]['Ip'] == ip.split('/')[0]:
            return key
    return None


def is_allowed_by_security_group(allowed_out, src_id, allowed_in, dst_id):
    if src_id is not None and dst_id is not None:
        return (len(list(set(allowed_out['Sg']).intersection(instances[dst_id]['SecurityGroups']))) > 0 and len(
            list(set(allowed_in['Sg']).intersection(instances[src_id]['SecurityGroups']))) > 0)
    return False


def is_allowed_by_ip(ip_addr, allowed_ips):
    for allowed_ip in allowed_ips:
        if IPNetwork(ip_addr) in IPNetwork(allowed_ip):
            return True
    return False


if __name__ == "__main__": main()