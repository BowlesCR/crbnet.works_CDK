from aws_cdk import (
    Duration,
    Stack,
    aws_s3 as s3,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_certificatemanager as acm,
    aws_iam as iam,
)
from constructs import Construct


class CRBNetworksStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, cert: acm.Certificate, domains: list[str], **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        bucket = s3.Bucket(
            self,
            id="bucket_crbnetworks",
            bucket_name="crbnet.works",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            cors=[
                s3.CorsRule(
                    allowed_methods=[s3.HttpMethods.GET],
                    allowed_origins=["*"],
                    allowed_headers=["Authorization", "Content-Length"],
                    exposed_headers=[],
                    max_age=3000,
                )
            ],
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,
            lifecycle_rules=[s3.LifecycleRule(id="Delete old logs", expiration=Duration.days(30), prefix="cf-logs/")],
        )

        cf = cloudfront.Distribution(
            self,
            id="distribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3Origin(bucket, origin_path="/html"),
                compress=True,
                function_associations=[
                    cloudfront.FunctionAssociation(
                        event_type=cloudfront.FunctionEventType.VIEWER_REQUEST,
                        function=cloudfront.Function.from_function_attributes(  # TODO: real construct
                            self,
                            "Spam",
                            function_name="Spam",
                            function_arn="arn:aws:cloudfront::491980376260:function/Spam",
                        ),
                    )
                ],
                origin_request_policy=cloudfront.OriginRequestPolicy.CORS_S3_ORIGIN,
                response_headers_policy=cloudfront.ResponseHeadersPolicy.from_response_headers_policy_id(
                    self, id="response_headers_policy", response_headers_policy_id="2790f410-a427-4767-88d5-fa0033ad4e84"
                ),  # TODO: real construct
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            ),
            certificate=cert,
            default_root_object="index.html",
            domain_names=domains,
            enable_ipv6=True,
            enable_logging=True,
            http_version=cloudfront.HttpVersion.HTTP2_AND_3,
            log_bucket=bucket,
            log_file_prefix="cf-logs/",
            minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
            price_class=cloudfront.PriceClass.PRICE_CLASS_100,
            error_responses=[
                cloudfront.ErrorResponse(http_status=code, response_http_status=code, response_page_path="/error.html", ttl=Duration.seconds(60))
                for code in [400, 403, 404, 405, 414, 416]
            ],
        )

        # Workarounds for lack of L2 OAC support - https://github.com/aws/aws-cdk/issues/21771#issuecomment-1567647338
        # https://github.com/aws/aws-cdk/issues/21771
        # https://github.com/aws/aws-cdk-rfcs/issues/491

        oac = cloudfront.CfnOriginAccessControl(
            self,
            "crbnetworks_OAC",
            origin_access_control_config=cloudfront.CfnOriginAccessControl.OriginAccessControlConfigProperty(
                name="crbnetworks_OAC_config",
                origin_access_control_origin_type="s3",
                signing_behavior="always",
                signing_protocol="sigv4",
            ),
        )

        bucket.add_to_resource_policy(
            iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("cloudfront.amazonaws.com")],
                actions=["s3:GetObject"],
                resources=[bucket.arn_for_objects("html/*")],
                conditions={"StringEquals": {"aws:sourceArn": f"arn:aws:cloudfront::{self.account}:distribution/{cf.distribution_id}"}},
            )
        )

        ## clean-up the OAI reference and associate the OAC with the cloudfront distribution
        # query the site bucket policy as a document
        bucket_policy = bucket.policy
        bucket_policy_document = bucket_policy.document

        # remove the CloudFront Origin Access Identity permission from the bucket policy
        if isinstance(bucket_policy_document, iam.PolicyDocument):
            bucket_policy_document_json = bucket_policy_document.to_json()
            # create an updated policy without the OAI reference
            bucket_policy_updated_json = {"Version": "2012-10-17", "Statement": []}
            for statement in bucket_policy_document_json["Statement"]:
                if "CanonicalUser" not in statement["Principal"]:
                    bucket_policy_updated_json["Statement"].append(statement)

        # apply the updated bucket policy to the bucket
        bucket_policy_override = bucket.node.find_child("Policy").node.default_child
        bucket_policy_override.add_override("Properties.PolicyDocument", bucket_policy_updated_json)

        # remove the created OAI reference (S3 Origin property) for the distribution
        all_distribution_props = cf.node.find_all()
        for child in all_distribution_props:
            if child.node.id == "S3Origin":
                child.node.try_remove_child("Resource")

        # associate the created OAC with the distribution
        distribution_props = cf.node.default_child
        distribution_props.add_override("Properties.DistributionConfig.Origins.0.S3OriginConfig.OriginAccessIdentity", "")
        distribution_props.add_property_override("DistributionConfig.Origins.0.OriginAccessControlId", oac.ref)
