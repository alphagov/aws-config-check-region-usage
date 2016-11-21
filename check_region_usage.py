import boto3
import json

from itertools import chain

"""
Check Region Usage
------------------

NOTE: This was built purely to test the functionality of AWS Config.

An AWS Config check to look for instances being created in regions outside of
what you expect. This could be used to catch mistaken use of another region or
treat as an indicator of possible AWS account compromise.

Given AWS Config rules are defined for each region it's not possible to have
this check run on creation of an EC2 instance without duplicating the rule
across all regions so it has been built to run periodically.

The following policy allows the function to list all available regions and the
instances defined within them.

    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:DescribeInstances",
                    "ec2:DescribeRegions"
                ],
                "Resource": "*"
            }
        ]
    }

Specify parameters for the allowed_regions:

    `allowed_regions: ["eu-west-1"]`

"""


def evaluate_compliance(rule_parameters):
    allowed_regions = rule_parameters['allowed_regions']
    ec2c = boto3.client('ec2')
    available_regions = [r['RegionName'] for r in ec2c.describe_regions()['Regions']]
    instances_by_region = dict([(reg, boto3.client('ec2', region_name=reg).describe_instances()['Reservations']) for reg in available_regions])
    noncompliant_instances = dict(filter(lambda (region, instances): (region not in allowed_regions) and instances, instances_by_region.items()))
    if noncompliant_instances:
        return {
            "compliance_type": "NON_COMPLIANT",
            "annotation": "Instances found in {0}. Reservations: {1}".format(
                noncompliant_instances.keys(),
                map(lambda i: i['ReservationId'], chain(*noncompliant_instances.values()))
            )
        }
    else:
        return {
            "compliance_type": "COMPLIANT",
            "annotation": "All instances are in allowed regions"
        }

def lambda_handler(event, context):

    invoking_event = json.loads(event["invokingEvent"])
    rule_parameters = json.loads(event["ruleParameters"])

    result_token = "No token found."
    if "resultToken" in event:
        result_token = event["resultToken"]

    evaluation = evaluate_compliance(rule_parameters)

    config = boto3.client("config")
    config.put_evaluations(
        Evaluations=[
            {
                "ComplianceResourceType": 'AWS::::Account',
                "ComplianceResourceId": event["accountId"],
                "ComplianceType": evaluation["compliance_type"],
                "Annotation": evaluation["annotation"],
                "OrderingTimestamp": invoking_event["notificationCreationTime"]
            },
        ],
        ResultToken=result_token
    )
