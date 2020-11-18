import collections
import copy
import hashlib
import json

import sg_exporter


# Used to track rule to ip range state
rule_ip_range_mapping = collections.defaultdict(list)
# Used to track rule to groups state
rule_groups_mapping = collections.defaultdict(list)


def update_security_groups(group_container, assume_role_arn, aws_region):
    """Update given security group container with SG data.

    :param group_container: A group container to use for tracking SG dataset.
    :type  group_container: dict

    :param assume_role_arn: A role ARN to use when assuming (optional).
    :param aws_region: An AWS region to use when assuming (optional).

    :rtype: set
    """
    removed_copies = copy.copy(group_container)
    next_token = None
    max_results = 500
    while True:
        params = {'MaxResults': max_results}
        if next_token:
            params['NextToken'] = next_token
        group_data = sg_exporter.ec2(assume_role_arn, aws_region).describe_security_groups(**params)
        for group in group_data['SecurityGroups']:
            group_id = group['GroupId']
            if group_id in group_container:
                # Update existing values
                group_container[group_id].update(group)
            else:
                group_container[group_id] = group
            if group_id in removed_copies:
                del removed_copies[group_id]
        if 'NextToken' in group_data:
            next_token = group_data['NextToken']
        else:
            break
    return set(removed_copies.keys())


def export_security_groups(group_container, removed_copies):
    """Export data on security groups"""

    for group_id, group_data in group_container.items():
        sg_exporter.aws_sg_info.labels(
            GroupId=group_data['GroupId'],
            GroupName=group_data['GroupName'],
        ).inc()
        export_security_group_rules(group_data, removed=False)

    for group_id in removed_copies:
        group_data = group_container[group_id]
        sg_exporter.aws_sg_info.labels(
            GroupId=group_data['GroupId'],
            GroupName=group_data['GroupName'],
        ).dec()
        group_container.pop(group_id)
        export_security_group_rules(group_data, removed=True)


def export_security_group_rules(group_data, removed=False):
    mapping = {
        'Ingress': 'IpPermissions',
        'Egress': 'IpPermissionsEgress',
    }

    for (traffic_type, rules_key) in mapping.items():
        for rule_data in group_data[rules_key]:

            rule_hash_id = hashlib.sha3_224(json.dumps(rule_data).encode()).hexdigest()

            metric = sg_exporter.aws_sg_rule_info.labels(
                GroupId=group_data['GroupId'],
                GroupName=group_data['GroupName'],
                RuleHashId=rule_hash_id,
                IpProtocol=rule_data['IpProtocol'],
                FromPort=rule_data.get('FromPort', '-1'),
                ToPort=rule_data.get('ToPort', '-1'),
                Type=traffic_type,
            )

            func = 'dec' if removed else 'inc'
            getattr(metric, func)()

            # Exports CIDR peering rules
            previous_ip_ranges = rule_ip_range_mapping.pop(rule_hash_id, [])
            for ip_range in rule_data['IpRanges']:
                cidr_ip = ip_range['CidrIp']
                ip_metric = sg_exporter.aws_sg_rule_ip_range.labels(
                    GroupId=group_data['GroupId'],
                    GroupName=group_data['GroupName'],
                    RuleHashId=rule_hash_id,
                    IpProtocol=rule_data['IpProtocol'],
                    FromPort=rule_data.get('FromPort', '-1'),
                    ToPort=rule_data.get('ToPort', '-1'),
                    IpRangeCidr=cidr_ip,
                    Type=traffic_type,
                )
                getattr(ip_metric, func)()
                if cidr_ip in previous_ip_ranges:
                    previous_ip_ranges.remove(cidr_ip)
                rule_ip_range_mapping[rule_hash_id].append(cidr_ip)

            for cidr_ip in previous_ip_ranges:
                ip_metric = sg_exporter.aws_sg_rule_ip_range.labels(
                    GroupId=group_data['GroupId'],
                    GroupName=group_data['GroupName'],
                    RuleHashId=rule_hash_id,
                    IpProtocol=rule_data['IpProtocol'],
                    FromPort=rule_data.get('FromPort', '-1'),
                    ToPort=rule_data.get('ToPort', '-1'),
                    IpRangeCidr=cidr_ip,
                    Type=traffic_type,
                )
                ip_metric.dec()

            # Exports SG peering rules
            previous_sg_user_pairs = rule_groups_mapping.pop(rule_hash_id, [])
            for user_sg_pair in rule_data.get('UserIdGroupPairs', []):
                gid = f'{user_sg_pair.get("UserId", user_sg_pair.get("VpcId"))}/{user_sg_pair["GroupId"]}'
                sg_peer_metric = sg_exporter.aws_sg_rule_sg_peer.labels(
                    GroupId=group_data['GroupId'],
                    GroupName=group_data['GroupName'],
                    RuleHashId=rule_hash_id,
                    IpProtocol=rule_data['IpProtocol'],
                    FromPort=rule_data.get('FromPort', '-1'),
                    ToPort=rule_data.get('ToPort', '-1'),
                    UserSecurityGroup=gid,
                    Type=traffic_type,
                )
                getattr(sg_peer_metric, func)()
                if gid in previous_sg_user_pairs:
                    previous_sg_user_pairs.remove(gid)
                rule_groups_mapping[rule_hash_id].append(gid)

            for gid in previous_sg_user_pairs:
                ip_metric = sg_exporter.aws_sg_rule_ip_range.labels(
                        GroupId=group_data['GroupId'],
                        GroupName=group_data['GroupName'],
                        RuleHashId=rule_hash_id,
                        IpProtocol=rule_data['IpProtocol'],
                        FromPort=rule_data.get('FromPort', '-1'),
                        ToPort=rule_data.get('ToPort', '-1'),
                        UserSecurityGroup=gid,
                        Type=traffic_type,
                )
                ip_metric.dec()
