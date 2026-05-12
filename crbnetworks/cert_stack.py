from aws_cdk import (
    Stack,
    aws_certificatemanager as acm,
)
from constructs import Construct


class CertStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, domains: list[str], **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.cert = acm.Certificate(
            self,
            "crbnetworks_cert",
            domain_name=domains[0],
            subject_alternative_names=domains[1:],  # Don't include the primary domain in the SANs list
            validation=acm.CertificateValidation.from_dns(),
        )
