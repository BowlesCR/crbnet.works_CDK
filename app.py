#!/usr/bin/env python3
import os

import aws_cdk as cdk

from crbnetworks.crbnetworks_stack import CRBNetworksStack
from crbnetworks.cert_stack import CertStack

app = cdk.App()

DOMAINS = ["crbnet.works", "www.crbnet.works"]
ACCOUNT = os.getenv("CDK_DEFAULT_ACCOUNT")

cert_stack = CertStack(
    app,
    "CertStack",
    env=cdk.Environment(account=ACCOUNT, region="us-east-1"),
    domains=DOMAINS,
    cross_region_references=True,
)

CRBNetworksStack(
    app,
    "CRBNetworksStack",
    env=cdk.Environment(account=ACCOUNT, region=os.getenv("CDK_DEFAULT_REGION")),
    cert=cert_stack.cert,
    domains=DOMAINS,
    cross_region_references=True,
)

cdk.Tags.of(app).add("App", "CRBNet.works")

app.synth()
