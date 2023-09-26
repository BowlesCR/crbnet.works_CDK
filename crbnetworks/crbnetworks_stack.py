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
                        function=cloudfront.Function(
                            self,
                            id="spam_function",
                            comment="Block obvious spam",
                            code=cloudfront.FunctionCode.from_file(file_path="crbnetworks/SpamFunction.js"),
                        ),
                    )
                ],
                origin_request_policy=cloudfront.OriginRequestPolicy.CORS_S3_ORIGIN,
                response_headers_policy=cloudfront.ResponseHeadersPolicy(
                    self,
                    id="crbnetworks_response_headers",
                    security_headers_behavior=cloudfront.ResponseSecurityHeadersBehavior(
                        strict_transport_security=cloudfront.ResponseHeadersStrictTransportSecurity(access_control_max_age=Duration.days(365), include_subdomains=True, preload=True, override=True),
                        content_type_options=cloudfront.ResponseHeadersContentTypeOptions(override=False),
                        frame_options=cloudfront.ResponseHeadersFrameOptions(frame_option=cloudfront.HeadersFrameOption.DENY, override=False),
                        xss_protection=cloudfront.ResponseHeadersXSSProtection(protection=True, mode_block=True, override=False),
                        referrer_policy=cloudfront.ResponseHeadersReferrerPolicy(referrer_policy=cloudfront.HeadersReferrerPolicy.SAME_ORIGIN, override=False),
                        content_security_policy=cloudfront.ResponseHeadersContentSecurityPolicy(content_security_policy="default-src 'none'; script-src 'self' https://code.jquery.com/ https://cdnjs.cloudflare.com/ https://stackpath.bootstrapcdn.com/; style-src 'self' https://cdn.jsdelivr.net/ https://fonts.googleapis.com/ https://use.fontawesome.com/; img-src 'self' data:; font-src https://use.fontawesome.com/ https://cdn.jsdelivr.net/ https://fonts.gstatic.com/; object-src 'none'; frame-ancestors 'none'; form-action 'none'; upgrade-insecure-requests; block-all-mixed-content; base-uri crbnet.works www.crbnet.works; manifest-src 'self'", override=False)
                    ),
                    custom_headers_behavior=cloudfront.ResponseCustomHeadersBehavior(custom_headers=[cloudfront.ResponseCustomHeader(header="permissions-policy", value="sync-xhr=()", override=False)]),
                ),
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
