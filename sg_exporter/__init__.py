import socket
import time

import boto3
import prometheus_client


client = None
assume_role_state = {}


def ec2(assume_role_arn, aws_region):
    global client
    if assume_role_arn and\
            ('renewal' not in assume_role_state or time.time() - assume_role_state.get('renewal', 0) > 3000):
        s = boto3.Session()
        sts = s.client('sts')
        assume_role_object = sts.assume_role(
                RoleArn=assume_role_arn,
                RoleSessionName=f'sg-exporter-{socket.gethostname()}',
                DurationSeconds=3600
        )
        client = boto3.client(
                'ec2',
                aws_access_key_id=assume_role_object['Credentials']['AccessKeyId'],
                aws_secret_access_key=assume_role_object['Credentials']['SecretAccessKey'],
                aws_session_token=assume_role_object['Credentials']['SessionToken'],
                region_name=aws_region,
        )
        assume_role_state['renewal'] = time.time()
    elif client is None:
        client = boto3.client('ec2')
    return client


sec_groups = {}

aws_sg_info = prometheus_client.Counter('aws_sg_info',
                                        documentation='AWS Security Group information',
                                        labelnames=('GroupId', 'GroupName'))
aws_sg_rule_info = prometheus_client.Counter('aws_sg_rule_info',
                                             documentation='AWS Security Group rule information',
                                             labelnames=('GroupId', 'GroupName', 'RuleHashId',
                                                         'FromPort', 'ToPort', 'IpProtocol', 'Type'))
aws_sg_rule_ip_range = prometheus_client.Counter('aws_sg_rule_ip_range',
                                                 documentation='AWS Security Group rule IP range info',
                                                 labelnames=('GroupId', 'GroupName', 'RuleHashId',
                                                             'FromPort', 'ToPort', 'IpProtocol', 'IpRangeCidr',
                                                             'Type'))
aws_sg_rule_sg_peer = prometheus_client.Counter('aws_sg_rule_sg_peer',
                                                documentation='AWS Security Group rule peered security group info',
                                                labelnames=('GroupId', 'GroupName', 'RuleHashId',
                                                            'FromPort', 'ToPort', 'IpProtocol', 'UserSecurityGroup',
                                                            'Type'))
