# Permission gap report

| Principal | Granted | Used | Stale | Unused | Unobservable | Unused % | High-risk unused |
|---|---:|---:|---:|---:|---:|---:|---:|
| `arn:aws:iam::111122223333:role/ci-deployer` | 207 | 8 | 0 | 197 | 2 | 95.2 | 95 |

## `arn:aws:iam::111122223333:role/ci-deployer`

Window 2026-07-01 to 2026-09-28; ages measured at 2026-09-28; stale after 30 days.

Grants outside the bundled catalog (not itemised below): `* (every action of every service, including services outside the catalog)`

High-risk unused grants: `dynamodb:BatchWriteItem`, `dynamodb:CreateTable`, `dynamodb:DeleteItem`, `dynamodb:DeleteTable`, `dynamodb:PutItem`, `dynamodb:UpdateItem`, `dynamodb:UpdateTable`, `dynamodb:UpdateTimeToLive`, `ec2:AttachVolume`, `ec2:AuthorizeSecurityGroupIngress`, `ec2:CreateSecurityGroup`, `ec2:CreateSnapshot`, `ec2:DetachVolume`, `ec2:RebootInstances`, `ec2:RevokeSecurityGroupIngress`, +80 more

| Service | Granted actions | Used | Unused | Last used |
|---|---:|---:|---:|---|
| dynamodb | 23 | 0 | 23 | never |
| ec2 | 21 | 0 | 21 | never |
| iam | 32 | 0 | 31 | never |
| kms | 21 | 0 | 21 | never |
| lambda | 15 | 6 | 9 | 2026-09-28 |
| logs | 12 | 0 | 11 | never |
| s3 | 32 | 2 | 30 | 2026-09-28 |
| secretsmanager | 11 | 0 | 11 | never |
| sns | 12 | 0 | 12 | never |
| sqs | 15 | 0 | 15 | never |
| ssm | 8 | 0 | 8 | never |
| sts | 5 | 0 | 5 | never |

| Action | Access | Status | Calls | Resources | Last used (age) | Risk | Notes |
|---|---|---|---:|---:|---|---|---|
| `dynamodb:BatchWriteItem` | Write | unused | 0 | 0 |  | high | recorded only as a CloudTrail data event; confirm data events were enabled |
| `dynamodb:CreateTable` | Write | unused | 0 | 0 |  | high |  |
| `dynamodb:DeleteItem` | Write | unused | 0 | 0 |  | high | recorded only as a CloudTrail data event; confirm data events were enabled |
| `dynamodb:DeleteTable` | Write | unused | 0 | 0 |  | high |  |
| `dynamodb:PutItem` | Write | unused | 0 | 0 |  | high | recorded only as a CloudTrail data event; confirm data events were enabled |
| `dynamodb:TagResource` | Tagging | unused | 0 | 0 |  | medium |  |
| `dynamodb:UntagResource` | Tagging | unused | 0 | 0 |  | medium |  |
| `dynamodb:UpdateItem` | Write | unused | 0 | 0 |  | high | recorded only as a CloudTrail data event; confirm data events were enabled |
| `dynamodb:UpdateTable` | Write | unused | 0 | 0 |  | high |  |
| `dynamodb:UpdateTimeToLive` | Write | unused | 0 | 0 |  | high |  |
| `ec2:AttachVolume` | Write | unused | 0 | 0 |  | high |  |
| `ec2:AuthorizeSecurityGroupIngress` | Write | unused | 0 | 0 |  | high |  |
| `ec2:CreateSecurityGroup` | Write | unused | 0 | 0 |  | high |  |
| `ec2:CreateSnapshot` | Write | unused | 0 | 0 |  | high |  |
| `ec2:CreateTags` | Tagging | unused | 0 | 0 |  | medium |  |
| `ec2:DeleteTags` | Tagging | unused | 0 | 0 |  | medium |  |
| `ec2:DetachVolume` | Write | unused | 0 | 0 |  | high |  |
| `ec2:RebootInstances` | Write | unused | 0 | 0 |  | high |  |
| `ec2:RevokeSecurityGroupIngress` | Write | unused | 0 | 0 |  | high |  |
| `ec2:RunInstances` | Write | unused | 0 | 0 |  | high |  |
| `ec2:StartInstances` | Write | unused | 0 | 0 |  | high |  |
| `ec2:StopInstances` | Write | unused | 0 | 0 |  | high |  |
| `ec2:TerminateInstances` | Write | unused | 0 | 0 |  | high |  |
| `iam:AddUserToGroup` | Write | unused | 0 | 0 |  | high |  |
| `iam:AttachRolePolicy` | Permissions management | unused | 0 | 0 |  | high |  |
| `iam:AttachUserPolicy` | Permissions management | unused | 0 | 0 |  | high |  |
| `iam:CreateAccessKey` | Write | unused | 0 | 0 |  | high |  |
| `iam:CreatePolicy` | Permissions management | unused | 0 | 0 |  | high |  |
| `iam:CreatePolicyVersion` | Permissions management | unused | 0 | 0 |  | high |  |
| `iam:CreateRole` | Write | unused | 0 | 0 |  | high |  |
| `iam:CreateUser` | Write | unused | 0 | 0 |  | high |  |
| `iam:DeleteAccessKey` | Write | unused | 0 | 0 |  | high |  |
| `iam:DeleteRole` | Write | unused | 0 | 0 |  | high |  |
| `iam:DeleteRolePolicy` | Permissions management | unused | 0 | 0 |  | high |  |
| `iam:DeleteUser` | Write | unused | 0 | 0 |  | high |  |
| `iam:DetachRolePolicy` | Permissions management | unused | 0 | 0 |  | high |  |
| `iam:PassRole` | Write | unobservable | 0 | 0 |  |  | CloudTrail does not record this action; usage cannot be observed |
| `iam:PutRolePolicy` | Permissions management | unused | 0 | 0 |  | high |  |
| `iam:PutUserPolicy` | Permissions management | unused | 0 | 0 |  | high |  |
| `iam:TagRole` | Tagging | unused | 0 | 0 |  | medium |  |
| `iam:UpdateAssumeRolePolicy` | Permissions management | unused | 0 | 0 |  | high |  |
| `kms:CreateAlias` | Write | unused | 0 | 0 |  | high |  |
| `kms:CreateGrant` | Permissions management | unused | 0 | 0 |  | high |  |
| `kms:CreateKey` | Write | unused | 0 | 0 |  | high |  |
| `kms:Decrypt` | Write | unused | 0 | 0 |  | high |  |
| `kms:EnableKeyRotation` | Write | unused | 0 | 0 |  | high |  |
| `kms:Encrypt` | Write | unused | 0 | 0 |  | high |  |
| `kms:GenerateDataKey` | Write | unused | 0 | 0 |  | high |  |
| `kms:GenerateDataKeyWithoutPlaintext` | Write | unused | 0 | 0 |  | high |  |
| `kms:PutKeyPolicy` | Permissions management | unused | 0 | 0 |  | high |  |
| `kms:ReEncryptFrom` | Write | unused | 0 | 0 |  | high |  |
| `kms:ReEncryptTo` | Write | unused | 0 | 0 |  | high |  |
| `kms:RetireGrant` | Permissions management | unused | 0 | 0 |  | high |  |
| `kms:ScheduleKeyDeletion` | Write | unused | 0 | 0 |  | high |  |
| `kms:Sign` | Write | unused | 0 | 0 |  | high |  |
| `kms:Verify` | Write | unused | 0 | 0 |  | high |  |
| `lambda:AddPermission` | Permissions management | unused | 0 | 0 |  | high |  |
| `lambda:CreateFunction` | Write | used | 3 | 1 | 2026-09-11 (17d) |  |  |
| `lambda:DeleteFunction` | Write | used | 1 | 1 | 2026-09-14 (14d) |  |  |
| `lambda:GetFunction` | Read | used | 196 | 6 | 2026-09-28 (0d) |  |  |
| `lambda:InvokeFunction` | Write | unused | 0 | 0 |  | high | recorded only as a CloudTrail data event; confirm data events were enabled |
| `lambda:PublishVersion` | Write | used | 128 | 3 | 2026-09-28 (0d) |  |  |
| `lambda:RemovePermission` | Permissions management | unused | 0 | 0 |  | high |  |
| `lambda:TagResource` | Tagging | unused | 0 | 0 |  | medium |  |
| `lambda:UpdateFunctionCode` | Write | used | 132 | 3 | 2026-09-28 (0d) |  |  |
| `lambda:UpdateFunctionConfiguration` | Write | used | 13 | 3 | 2026-09-24 (4d) |  |  |
| `logs:CreateLogGroup` | Write | unused | 0 | 0 |  | high |  |
| `logs:CreateLogStream` | Write | unused | 0 | 0 |  | high |  |
| `logs:DeleteLogGroup` | Write | unused | 0 | 0 |  | high |  |
| `logs:PutLogEvents` | Write | unobservable | 0 | 0 |  |  | CloudTrail does not record this action; usage cannot be observed |
| `logs:PutRetentionPolicy` | Write | unused | 0 | 0 |  | high |  |
| `logs:TagResource` | Tagging | unused | 0 | 0 |  | medium |  |
| `s3:AbortMultipartUpload` | Write | unused | 0 | 0 |  | high | recorded only as a CloudTrail data event; confirm data events were enabled |
| `s3:CreateBucket` | Write | unused | 0 | 0 |  | high |  |
| `s3:DeleteBucket` | Write | unused | 0 | 0 |  | high |  |
| `s3:DeleteBucketPolicy` | Permissions management | unused | 0 | 0 |  | high |  |
| `s3:DeleteObject` | Write | unused | 0 | 0 |  | high | recorded only as a CloudTrail data event; confirm data events were enabled |
| `s3:GetObject` | Read | used | 128 | 128 | 2026-09-28 (0d) |  |  |
| `s3:PutBucketAcl` | Permissions management | unused | 0 | 0 |  | high |  |
| `s3:PutBucketPolicy` | Permissions management | unused | 0 | 0 |  | high |  |
| `s3:PutBucketPublicAccessBlock` | Permissions management | unused | 0 | 0 |  | high |  |
| `s3:PutBucketTagging` | Tagging | unused | 0 | 0 |  | medium |  |
| `s3:PutBucketVersioning` | Write | unused | 0 | 0 |  | high |  |
| `s3:PutEncryptionConfiguration` | Write | unused | 0 | 0 |  | high |  |
| `s3:PutLifecycleConfiguration` | Write | unused | 0 | 0 |  | high |  |
| `s3:PutObject` | Write | used | 125 | 125 | 2026-09-28 (0d) |  |  |
| `s3:PutObjectAcl` | Permissions management | unused | 0 | 0 |  | high | recorded only as a CloudTrail data event; confirm data events were enabled |
| `s3:PutObjectTagging` | Tagging | unused | 0 | 0 |  | medium | recorded only as a CloudTrail data event; confirm data events were enabled |
| `secretsmanager:CreateSecret` | Write | unused | 0 | 0 |  | high |  |
| `secretsmanager:DeleteSecret` | Write | unused | 0 | 0 |  | high |  |
| `secretsmanager:PutResourcePolicy` | Permissions management | unused | 0 | 0 |  | high |  |
| `secretsmanager:PutSecretValue` | Write | unused | 0 | 0 |  | high |  |
| `secretsmanager:RotateSecret` | Write | unused | 0 | 0 |  | high |  |
| `secretsmanager:TagResource` | Tagging | unused | 0 | 0 |  | medium |  |
| `secretsmanager:UpdateSecret` | Write | unused | 0 | 0 |  | high |  |
| `sns:AddPermission` | Permissions management | unused | 0 | 0 |  | high |  |
| `sns:CreateTopic` | Write | unused | 0 | 0 |  | high |  |
| `sns:DeleteTopic` | Write | unused | 0 | 0 |  | high |  |
| `sns:Publish` | Write | unused | 0 | 0 |  | high | recorded only as a CloudTrail data event; confirm data events were enabled |
| `sns:RemovePermission` | Permissions management | unused | 0 | 0 |  | high |  |
| `sns:SetTopicAttributes` | Write | unused | 0 | 0 |  | high |  |
| `sns:Subscribe` | Write | unused | 0 | 0 |  | high |  |
| `sns:TagResource` | Tagging | unused | 0 | 0 |  | medium |  |
| `sqs:AddPermission` | Permissions management | unused | 0 | 0 |  | high |  |
| `sqs:ChangeMessageVisibility` | Write | unused | 0 | 0 |  | high | recorded only as a CloudTrail data event; confirm data events were enabled |
| `sqs:CreateQueue` | Write | unused | 0 | 0 |  | high |  |
| `sqs:DeleteMessage` | Write | unused | 0 | 0 |  | high | recorded only as a CloudTrail data event; confirm data events were enabled |
| `sqs:DeleteQueue` | Write | unused | 0 | 0 |  | high |  |
| `sqs:PurgeQueue` | Write | unused | 0 | 0 |  | high |  |
| `sqs:RemovePermission` | Permissions management | unused | 0 | 0 |  | high |  |
| `sqs:SendMessage` | Write | unused | 0 | 0 |  | high | recorded only as a CloudTrail data event; confirm data events were enabled |
| `sqs:SetQueueAttributes` | Write | unused | 0 | 0 |  | high |  |
| `sqs:TagQueue` | Tagging | unused | 0 | 0 |  | medium |  |
| `ssm:AddTagsToResource` | Tagging | unused | 0 | 0 |  | medium |  |
| `ssm:DeleteParameter` | Write | unused | 0 | 0 |  | high |  |
| `ssm:PutParameter` | Write | unused | 0 | 0 |  | high |  |
| `sts:AssumeRole` | Write | unused | 0 | 0 |  | high |  |
| `sts:DecodeAuthorizationMessage` | Write | unused | 0 | 0 |  | high |  |
| `sts:GetCallerIdentity` | Read | no-auth | 64 | 1 | 2026-09-28 (0d) |  |  |
| `sts:TagSession` | Tagging | unused | 0 | 0 |  | medium |  |

Low-risk unused actions are counted above and listed in the JSON report.
