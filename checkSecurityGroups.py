import boto3
import json
import re
from netaddr import IPNetwork
from argparse import ArgumentParser
import sys
import glob

client = boto3.client('ec2')
instances = {}
security_groups = {}
check_running = True
verbose = False


def main():
    global verbose
    global check_running
    argument_parser = ArgumentParser(description='Verify AWS security group configuration for instances')
    argument_parser.add_argument('-v', '--verbose', action='store_true', dest='verbose', default=False,
                                 help='Turn on verbose output')
    argument_parser.add_argument('--security-groups',
                                 help='Path to security group json(s), instead of running configuration')
    argument_parser.add_argument('--expected-rules',
                                 help='Path to expected rules to test against in json-file(s)',
                                 default='expected_rules.json')
    arguments = argument_parser.parse_args()
    verbose = arguments.verbose
    status = 0
    rules = load_expected_rules_from_directory(arguments.expected_rules)
    if arguments.security_groups is not None:
        check_running = False
        load_security_groups_from_directory(arguments.security_groups)
    set_instances_and_security_groups()
    rules = expand_wildcard_rules(rules)
    for rule in rules:
        allowed = 'Allow' if rule['IsAllowed'] else 'Deny'
        rule_ok = is_rule_ok(rule)
        if not rule_ok or verbose:
            print(allowed + ' from ' + rule['Source'] + ' to ' + rule['Destination'] + ' ' + rule[
                'ProtocolAndRange'] + ' = ' + str(rule_ok))
            status = status + (0 if rule_ok else 1)
    sys.exit(status)


def load_security_groups_from_directory(security_groups_path):
    if not security_groups_path.endswith('.json'):
        files = glob.glob(security_groups_path + '*.json')
        for file_name in files:
            load_security_group_from_file(file_name)
    else:
        load_security_group_from_file(security_groups_path)


def load_security_group_from_file(file_name):
    sg = load_json_from_file(file_name)['SecurityGroups'][0]
    security_groups[sg['GroupId']] = sg


def load_json_from_file(file_name):
    with open(file_name) as json_object:
        return json.load(json_object)


def load_expected_rules_from_directory(expected_rules_path):
    rules = []
    if not expected_rules_path.endswith('.json'):
        files = glob.glob(expected_rules_path + '*.json')
        for file_name in files:
            rules.extend(load_json_from_file(file_name))
    else:
        rules.extend(load_json_from_file(expected_rules_path))
    return rules


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
        if group['GroupId'] not in security_groups:
            if not check_running:
                print(group['GroupId'] + ' not in local directory, fetching from running configuration')
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


def expand_wildcard_rules(rules):
    rules.extend(expand(filter(lambda rule: rule['Destination'] == '*', rules), 'Destination'))
    rules.extend(expand(filter(lambda rule: rule['Source'] == '*', rules), 'Source'))
    return filter(lambda rule: (rule['Destination'] != '*' and rule['Source'] != '*'), rules)


def expand(wildcards, source_or_destination):
    expanded = []
    for wildcard in wildcards:
        for instance in instances:
            if instances[instance]['Name'] != wildcard[source_or_destination]:
                rule = {u'ProtocolAndRange': wildcard['ProtocolAndRange'], u'IsAllowed': wildcard['IsAllowed']}
                if source_or_destination == 'Source':
                    rule['Source'] = instances[instance]['Name']
                    rule['Destination'] = wildcard['Destination']
                else:
                    rule['Destination'] = instances[instance]['Name']
                    rule['Source'] = wildcard['Source']
                expanded.append(rule)
    return expanded


def is_rule_ok(rule):
    rule_ok = False
    src_id = get_instance_id(rule['Source'])
    dst_id = get_instance_id(rule['Destination'])
    protocol = rule['ProtocolAndRange'].split('/')[0]
    port_range = rule['ProtocolAndRange'].split('/')[1]
    allowed_out = get_allowed(src_id, 'EffectiveOutgoing', protocol, port_range)
    allowed_in = get_allowed(dst_id, 'EffectiveIncoming', protocol, port_range)

    if (is_allowed_by_security_group(allowed_out, src_id, allowed_in, dst_id)
        or is_allowed_by_ip(rule['Source'], allowed_in['Ip'])
        or is_allowed_by_ip(rule['Destination'], allowed_out['Ip'])) == rule['IsAllowed']:
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
