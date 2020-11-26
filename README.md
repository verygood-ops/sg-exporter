sg-exporter
===========

Exports information on

 - AWS VPC security groups
 - inbound/outbound rules for AWS security groups
 - peered AWS security groups or IP CIDR ranges

to Prometheus.

How to use
----------

```
python3 -m sg_exporter
```

will start Prometheus metric exporter server on 10431 port.

```
python3 -m sg_exporter --interval=60
```

will make Prometheus metric exporter update security group data with interval of one minute.
By default, it is updated once per 5 minutes.

Configuration & Authentication
-------------------------------
`sg-exporter` uses `boto3` internally, so its configuration
[docs](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html) apply to this software.

Pass `--assume-role-arn` command line option to assume particular role when retrieving data.

Testing
-------

`python3 -m unittest`

LICENSE
-------
MIT.
