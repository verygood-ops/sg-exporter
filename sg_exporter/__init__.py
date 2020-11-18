import boto3
import prometheus_client


client = None


def ec2():
    global client
    if client is None:
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
