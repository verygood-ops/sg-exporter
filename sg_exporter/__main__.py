import argparse
import functools
import logging
import sys
import threading
import time

import prometheus_client

import sg_exporter
import sg_exporter.security_groups


logger = logging.getLogger(__name__)
arg_parser = argparse.ArgumentParser('AWS VPC Security Groups Exporter')
arg_parser.add_argument('-i', '--interval', default=300, type=int,
                        help='How often to update Security Group layout')
arg_parser.add_argument('-p', '--port', default=10431, type=int,
                        help='A port to serve metrics on')
arg_parser.add_argument('-I', '--assume-role-arn', default='',
                        help='Optional IAM role to assume')
arg_parser.add_argument('-r', '--aws-region', default='us-east-1',
                        help='AWS Region to use')
stopping = False
initialized = threading.Event()


def scraper_thread(interval, assume_role_arn, aws_region):
    """Indefinitely update security group data."""
    global stopping
    while not stopping:
        removed_keys = sg_exporter.security_groups.update_security_groups(
            sg_exporter.sec_groups,
            assume_role_arn,
            aws_region,
        )
        sg_exporter.security_groups.export_security_groups(sg_exporter.sec_groups, removed_keys)
        initialized.set()
        logger.warning('Updated AWS Security Group data')
        time.sleep(interval)


def main():
    global stopping
    logging.basicConfig(stream=sys.stdout)
    args = arg_parser.parse_args()
    initialized.clear()
    threading.Thread(
        target=functools.partial(
            scraper_thread,
            interval=args.interval,
            assume_role_arn=args.assume_role_arn,
            aws_region=args.aws_region,
        )
    ).start()
    # Prevent exporting empty metrics
    initialized.wait()
    logger.warning('Starting Prometheus metrics server')
    try:
        prometheus_client.start_http_server(port=args.port)
    except KeyboardInterrupt:
        stopping = True
        logger.exception('Preparing to shutdown ...')
        time.sleep(args.interval)


if __name__ == '__main__':
    main()
