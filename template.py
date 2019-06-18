#!/usr/bin/env python

"""
Template to generate KMS Key, Bucket and replication role
"""

from datetime import datetime as dt
from boto3 import client
from troposphere import (
    Template, Parameter, Output,
    GetAtt, Sub, Ref
)

from troposphere import (
    Condition, Equals,
    Not, If
)

from troposphere.iam import (
    Role as IamRole,
    Policy as IamPolicy
)

from troposphere.s3 import (
    Bucket,
    BucketPolicy
)

from troposphere.kms import (
    Key as KmsKey,
    Alias as KmsAlias
)

from troposphere.s3 import (
    Bucket,
    LifecycleConfiguration,
    LifecycleRule,
    LifecycleRuleTransition,
    VersioningConfiguration,
    AbortIncompleteMultipartUpload,
    BucketEncryption,
    SseKmsEncryptedObjects,
    SourceSelectionCriteria,
    ServerSideEncryptionRule,
    ServerSideEncryptionByDefault,
    ReplicationConfiguration,
    ReplicationConfigurationRules,
    ReplicationConfigurationRulesDestination,
    EncryptionConfiguration
)

from ozone.resources.iam.roles import role_trust_policy

TPL = Template('Template to create Replicated Bucket')
TPL.set_metadata({
    'Author': 'https://github.com/johnpreston',
    'Date': dt.utcnow().isoformat()
})

SOURCE_REGION = TPL.add_parameter(Parameter(
    'SourceRegion',
    Type='String',
    AllowedValues=[region['RegionName'] for region in client('ec2').describe_regions()['Regions']]
))

REPLICA_REGION = TPL.add_parameter(Parameter(
    'ReplicaRegion',
    Type='String',
    AllowedValues=[region['RegionName'] for region in client('ec2').describe_regions()['Regions']]
))

BUCKET_NAME = TPL.add_parameter(Parameter(
    'BucketName',
    Type='String',
    AllowedPattern=r'[a-z0-9-]+'
))

SOURCE_REGION_CON = TPL.add_condition(
    'IsSourceRegion', Equals(Ref(SOURCE_REGION), Ref('AWS::Region'))
)

REPLICA_REGION_CON = TPL.add_condition(
    'IsDestinationRegion', Equals(Ref(REPLICA_REGION), Ref('AWS::Region'))
)

KMS_KEY = TPL.add_resource(KmsKey(
    'BucketEncryptionKey',
    KeyPolicy={
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Allow administration of the key",
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        Sub("arn:aws:iam::${AWS::AccountId}:root")
                    ]
                },
                "Action": [
                    "kms:*"
                ],
                "Resource": ["*"]
            }
        ]
    }
))

KMS_ALIAS = TPL.add_resource(KmsAlias(
    'BucketEncryptionKeyAlias',
    TargetKeyId=GetAtt(KMS_KEY, 'Arn'),
    AliasName=Sub(f"alias/${{AWS::Region}}/${{{BUCKET_NAME.title}}}")
))

IAM_ROLE = TPL.add_resource(IamRole(
    'ReplicationRole',
    AssumeRolePolicyDocument=role_trust_policy('s3'),
    Condition=SOURCE_REGION_CON,
    Policies=[
        IamPolicy(
            PolicyName=Sub('KMSAccess'),
            PolicyDocument={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": [
                            "kms:Decrypt"
                        ],
                        "Effect": "Allow",
                        "Condition": {
                            "StringLike": {
                                "kms:ViaService": Sub(f"s3.${{{SOURCE_REGION.title}}}.${{AWS::URLSuffix}}")
                            }
                        },
                        "Resource": [
                            GetAtt(KMS_KEY, 'Arn')
                        ]
                    },
                    {
                        "Action": [
                            "kms:Encrypt"
                        ],
                        "Effect": "Allow",
                        "Condition": {
                            "StringLike": {
                                "kms:ViaService": Sub(f"s3.${{{REPLICA_REGION.title}}}.${{AWS::URLSuffix}}")
                            }
                        },
                        "Resource": [
                            Sub(f"arn:${{AWS::Partition}}:kms:${{{REPLICA_REGION.title}}}:${{AWS::AccountId}}:alias/${{{REPLICA_REGION.title}}}/${{{BUCKET_NAME.title}}}"),
                        ]
                    }
                ]
            }
        ),
        IamPolicy(
            PolicyName="S3ReplicationAccess",
            PolicyDocument={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": [
                            "s3:ListBucket",
                            "s3:GetReplicationConfiguration",
                            "s3:GetObjectVersionForReplication",
                            "s3:GetObjectVersionAcl",
                            "s3:GetObjectVersionTagging"
                        ],
                        "Effect": "Allow",
                        "Resource": [
                            Sub(f"arn:${{AWS::Partition}}:s3:::${{{BUCKET_NAME.title}}}-${{{SOURCE_REGION.title}}}"),
                            Sub(f"arn:${{AWS::Partition}}:s3:::${{{BUCKET_NAME.title}}}-${{{SOURCE_REGION.title}}}/*")
                        ]
                    },
                    {
                        "Action": [
                            "s3:ReplicateObject",
                            "s3:ReplicateDelete",
                            "s3:ReplicateTags",
                            "s3:GetObjectVersionTagging"
                        ],
                        "Effect": "Allow",
                        "Resource": [
                            Sub(f"arn:${{AWS::Partition}}:s3:::${{{BUCKET_NAME.title}}}-${{{REPLICA_REGION.title}}}"),
                            Sub(f"arn:${{AWS::Partition}}:s3:::${{{BUCKET_NAME.title}}}-${{{REPLICA_REGION.title}}}/*")
                        ]
                    }
                ]
            }
        )
    ]
))

BUCKET = Bucket(
    'ReplicatedBucket',
    DependsOn=[
        KMS_KEY,
        KMS_ALIAS
    ],
    BucketName=Sub('${BucketName}-${AWS::Region}'),
    VersioningConfiguration=VersioningConfiguration(
        Status='Enabled'
    ),
    LifecycleConfiguration=LifecycleConfiguration(
        Rules=[
            LifecycleRule(
                Status='Enabled',
                AbortIncompleteMultipartUpload=AbortIncompleteMultipartUpload(
                    DaysAfterInitiation=3
                ),
                NoncurrentVersionExpirationInDays=1,
                Transition=LifecycleRuleTransition(
                    StorageClass='GLACIER',
                    TransitionInDays=If(SOURCE_REGION_CON, 31, 14)
                )
            )
        ]
    ),
    BucketEncryption=BucketEncryption(
        ServerSideEncryptionConfiguration=[
            ServerSideEncryptionRule(
                ServerSideEncryptionByDefault=ServerSideEncryptionByDefault(
                    SSEAlgorithm='aws:kms',
                    KMSMasterKeyID=Ref(KMS_KEY)
                )
            )
        ]
    ),
    ReplicationConfiguration=If(
        SOURCE_REGION_CON,
        ReplicationConfiguration(
            Role=GetAtt(IAM_ROLE, 'Arn'),
            Rules=[
                ReplicationConfigurationRules(
                    Destination=ReplicationConfigurationRulesDestination(
                        Bucket=Sub(f"arn:${{AWS::Partition}}:s3:::${{{BUCKET_NAME.title}}}-${{{REPLICA_REGION.title}}}"),
                        EncryptionConfiguration=EncryptionConfiguration(
                            ReplicaKmsKeyID=Sub(f"arn:${{AWS::Partition}}:kms:${{{REPLICA_REGION.title}}}:${{AWS::AccountId}}:alias/${{{REPLICA_REGION.title}}}/${{{BUCKET_NAME.title}}}")
                        )
                    ),
                    SourceSelectionCriteria=SourceSelectionCriteria(
                        SseKmsEncryptedObjects=SseKmsEncryptedObjects(
                            Status='Enabled'
                        )
                    ),
                    Status='Enabled',
                    Prefix=''
                )
            ]
        ),
        Ref("AWS::NoValue")
    )
)
TPL.add_resource(BUCKET)

BUCKET_POLICY = BucketPolicy(
    'ReplicaBucketPolicy',
    Condition=REPLICA_REGION_CON,
    Bucket=Ref(BUCKET),
    PolicyDocument={
        "Version": "2008-10-17",
        "Id": "S3ReplicationPolicy",
        "Statement": [
            {
                "Sid": "S3ReplicationPolicy",
                "Effect": "Allow",
                "Principal": {
                    "AWS": Sub("arn:aws:iam::${AWS::AccountId}:root")
                },
                "Action": [
                    "s3:GetBucketVersioning",
                    "s3:PutBucketVersioning",
                    "s3:ReplicateObject",
                    "s3:ReplicateDelete"
                ],
                "Resource": [
                    Sub(f"arn:aws:s3:::${{{BUCKET.title}}}"),
                    Sub(f"arn:aws:s3:::${{{BUCKET.title}}}/*")
                ]
            }
        ]
    }
)
TPL.add_resource(BUCKET_POLICY)
TPL.add_output(Output('RoleArn', Value=If(SOURCE_REGION_CON, GetAtt(IAM_ROLE, 'Arn'), 'NoWhatWeNeedHere')))
print(TPL.to_yaml())
