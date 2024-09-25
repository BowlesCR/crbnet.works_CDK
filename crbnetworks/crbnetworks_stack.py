from aws_cdk import (
    Duration,
    Stack,
    aws_s3 as s3,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_certificatemanager as acm,
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
                    allowed_headers=[
                        "Authorization",
                        "Content-Length",
                    ],
                    exposed_headers=[],
                    max_age=3000,
                )
            ],
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="Delete old logs",
                    expiration=Duration.days(30),
                    prefix="cf-logs/",
                ),
            ],
        )

        oac = cloudfront.S3OriginAccessControl(
            self,
            "crbnetworks_OAC",
            origin_access_control_name="crbnetworks_OAC_config",
            signing=cloudfront.Signing.SIGV4_ALWAYS,
        )

        cloudfront.Distribution(
            self,
            id="distribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(bucket, origin_path="/html", origin_access_control=oac),
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
                        strict_transport_security=cloudfront.ResponseHeadersStrictTransportSecurity(
                            access_control_max_age=Duration.days(365),
                            include_subdomains=True,
                            preload=True,
                            override=True,
                        ),
                        content_type_options=cloudfront.ResponseHeadersContentTypeOptions(override=False),
                        frame_options=cloudfront.ResponseHeadersFrameOptions(
                            frame_option=cloudfront.HeadersFrameOption.DENY,
                            override=False,
                        ),
                        xss_protection=cloudfront.ResponseHeadersXSSProtection(
                            protection=True,
                            mode_block=True,
                            override=False,
                        ),
                        referrer_policy=cloudfront.ResponseHeadersReferrerPolicy(
                            referrer_policy=cloudfront.HeadersReferrerPolicy.SAME_ORIGIN,
                            override=False,
                        ),
                        content_security_policy=cloudfront.ResponseHeadersContentSecurityPolicy(
                            content_security_policy="default-src 'none'; script-src 'self' https://code.jquery.com/ https://cdnjs.cloudflare.com/ https://stackpath.bootstrapcdn.com/; style-src 'self' https://cdn.jsdelivr.net/ https://fonts.googleapis.com/ https://use.fontawesome.com/; img-src 'self' data:; font-src https://use.fontawesome.com/ https://cdn.jsdelivr.net/ https://fonts.gstatic.com/; object-src 'none'; frame-ancestors 'none'; form-action 'none'; upgrade-insecure-requests; block-all-mixed-content; base-uri crbnet.works www.crbnet.works; manifest-src 'self'",
                            override=False,
                        ),
                    ),
                    custom_headers_behavior=cloudfront.ResponseCustomHeadersBehavior(
                        custom_headers=[
                            cloudfront.ResponseCustomHeader(
                                header="permissions-policy",
                                value="sync-xhr=()",
                                override=False,
                            )
                        ]
                    ),
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
                cloudfront.ErrorResponse(
                    http_status=code,
                    response_http_status=code,
                    response_page_path="/error.html",
                    ttl=Duration.seconds(60),
                )
                for code in [400, 403, 404, 405, 414, 416]
            ],
        )
