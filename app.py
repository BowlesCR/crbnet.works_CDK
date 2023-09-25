#!/usr/bin/env python3
import os

import aws_cdk as cdk

from crbnetworks.crbnetworks_stack import CRBNetworksStack
from crbnetworks.cert_stack import CertStack

app = cdk.App()

DOMAINS = ["crbnet.works", "www.crbnet.works"]

cert_stack = CertStack(
    app,
    "CertStack",
    env=cdk.Environment(
        account=os.getenv("CDK_DEFAULT_ACCOUNT"),
        region="us-east-1",
    ),
    domains=DOMAINS,
    cross_region_references=True,
)

cdk.Tags.of(cert_stack).add("App", "CRBNet.works")

crbnetworks_stack = CRBNetworksStack(
    app,
    "CRBNetworksStack",
    env=cdk.Environment(
        account=os.getenv("CDK_DEFAULT_ACCOUNT"),
        region=os.getenv("CDK_DEFAULT_REGION"),
    ),
    cert=cert_stack.cert,
    domains=DOMAINS,
    cross_region_references=True,
)
cdk.Tags.of(crbnetworks_stack).add("App", "CRBNet.works")

app.synth()
