import json
import os
import types
import unittest
from unittest import mock

import prometheus_client


class FakeAWSAPIMethod:
    def __init__(self, fixture_name, method_name):
        self.name = fixture_name
        setattr(self, method_name, types.MethodType(lambda *args, **kwargs: self.load_fixture(), self))

    def load_fixture(self):
        dir_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'test'))
        with open(f'{dir_path}/fake_{self.name}.json') as fl:
            return json.loads(fl.read())


class SGExporterTest(unittest.TestCase):

    @mock.patch('sg_exporter.ec2', return_value=FakeAWSAPIMethod('boto_data', 'describe_security_groups'))
    def test_export_sg_content(self, ec2_describe_sg):
        import sg_exporter.security_groups

        removed_keys = sg_exporter.security_groups.update_security_groups(sg_exporter.sec_groups, None)
        sg_exporter.security_groups.export_security_groups(sg_exporter.sec_groups, removed_keys)
        metrics = prometheus_client.exposition.generate_latest().decode().splitlines()

        etalon_list = [
            # SG info
            'aws_sg_info_total{GroupId="sg-618ac7cb0d1f7d923",GroupName="test-access"} '
            '1.0',
            'aws_sg_info_total{GroupId="sg-2b49d04cef8c8627a",GroupName="test-access-2"} '
            '1.0',

            # SG Rule info
            'aws_sg_rule_info_total{FromPort="11001",'
            'GroupId="sg-618ac7cb0d1f7d923",GroupName="test-access",IpProtocol="tcp",'
            'RuleHashId="6b90f6b721460de7700b1ea694d308743ad622863c6535f633d316b3",ToPort="11001",Type="Ingress"} '
            '1.0',
            'aws_sg_rule_info_total{FromPort="11002",'
            'GroupId="sg-618ac7cb0d1f7d923",GroupName="test-access",IpProtocol="tcp",'
            'RuleHashId="dee92e90f071ecd37c87a50510bc305294167576b2109b8483d4da3d",ToPort="11002",Type="Ingress"} '
            '1.0',
            'aws_sg_rule_info_total{FromPort="443",'
            'GroupId="sg-2b49d04cef8c8627a",GroupName="test-access-2",IpProtocol="tcp",'
            'RuleHashId="cbb022cfd61b78ea2953ea8de82986a866bea67c2b4d42fb016e7fad",ToPort="443",Type="Ingress"} '
            '1.0',

            # Ip Range info
            'aws_sg_rule_ip_range_total{FromPort="443",'
            'GroupId="sg-2b49d04cef8c8627a",GroupName="test-access-2",'
            'IpProtocol="tcp",IpRangeCidr="0.0.0.0/0",'
            'RuleHashId="cbb022cfd61b78ea2953ea8de82986a866bea67c2b4d42fb016e7fad",ToPort="443",Type="Ingress"} '
            '1.0',

            # Ip Range Egress info
            'aws_sg_rule_ip_range_total{FromPort="-1",'
            'GroupId="sg-618ac7cb0d1f7d923",GroupName="test-access",IpProtocol="-1",IpRangeCidr="0.0.0.0/0",'
            'RuleHashId="031b1d17799d7a37c0243599773988113aaeea77c2cfae149829dd0f",ToPort="-1",Type="Egress"} '
            '1.0',
            'aws_sg_rule_ip_range_total{FromPort="-1",'
            'GroupId="sg-2b49d04cef8c8627a",GroupName="test-access-2",IpProtocol="-1",'
            'IpRangeCidr="0.0.0.0/0",RuleHashId="27d76082e4ca8a8859d33d061bc2ca4a5d280dc9fd9ad862c868ab17",'
            'ToPort="-1",Type="Egress"} '
            '1.0',
            # SG peering info
            'aws_sg_rule_sg_peer_total{FromPort="11001",'
            'GroupId="sg-618ac7cb0d1f7d923",GroupName="test-access",IpProtocol="tcp",'
            'RuleHashId="6b90f6b721460de7700b1ea694d308743ad622863c6535f633d316b3",'
            'ToPort="11001",Type="Ingress",UserSecurityGroup="483483734324/sg-e9697408a47015c2a"} '
            '1.0',
            'aws_sg_rule_sg_peer_total{FromPort="11001",'
            'GroupId="sg-618ac7cb0d1f7d923",GroupName="test-access",IpProtocol="tcp",'
            'RuleHashId="6b90f6b721460de7700b1ea694d308743ad622863c6535f633d316b3",ToPort="11001",Type="Ingress",'
            'UserSecurityGroup="483483734324/sg-87e2191bbb888f162"} '
            '1.0',
            'aws_sg_rule_sg_peer_total{FromPort="11002",'
            'GroupId="sg-618ac7cb0d1f7d923",GroupName="test-access",IpProtocol="tcp",'
            'RuleHashId="dee92e90f071ecd37c87a50510bc305294167576b2109b8483d4da3d",ToPort="11002",Type="Ingress",'
            'UserSecurityGroup="483483734324/sg-f22cea4be3feaec90"} '
            '1.0',
            'aws_sg_rule_sg_peer_total{FromPort="11002",'
            'GroupId="sg-618ac7cb0d1f7d923",GroupName="test-access",IpProtocol="tcp",'
            'RuleHashId="dee92e90f071ecd37c87a50510bc305294167576b2109b8483d4da3d",ToPort="11002",Type="Ingress",'
            'UserSecurityGroup="483483734324/sg-9cbc5f12687c27c4c"} '
            '1.0',
        ]
        for item in etalon_list:
            self.assertIn(item, metrics)
