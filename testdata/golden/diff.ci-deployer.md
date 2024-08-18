# Policy diff

Statements 2 -> 4; size 316 -> 1443 characters.

| Removed | Narrowed | Widened | Added | Changed | Unchanged |
|---:|---:|---:|---:|---:|---:|
| 200 | 8 | 0 | 0 | 0 | 0 |

- **narrowed** `lambda:CreateFunction`: `* if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}` -> `arn:aws:lambda:us-east-1:111122223333:function:deploy-reports if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}`
- **narrowed** `lambda:DeleteFunction`: `* if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}` -> `arn:aws:lambda:us-east-1:111122223333:function:deploy-reports if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}`
- **narrowed** `lambda:GetFunction`: `* if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}` -> `arn:aws:lambda:us-east-1:111122223333:function:deploy-api if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}`, `arn:aws:lambda:us-east-1:111122223333:function:deploy-cron if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}`, `arn:aws:lambda:us-east-1:111122223333:function:deploy-worker if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}`, +3 more
- **narrowed** `lambda:PublishVersion`: `* if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}` -> `arn:aws:lambda:us-east-1:111122223333:function:deploy-api if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}`, `arn:aws:lambda:us-east-1:111122223333:function:deploy-cron if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}`, `arn:aws:lambda:us-east-1:111122223333:function:deploy-worker if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}`
- **narrowed** `lambda:UpdateFunctionCode`: `* if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}` -> `arn:aws:lambda:us-east-1:111122223333:function:deploy-api if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}`, `arn:aws:lambda:us-east-1:111122223333:function:deploy-cron if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}`, `arn:aws:lambda:us-east-1:111122223333:function:deploy-worker if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}`
- **narrowed** `lambda:UpdateFunctionConfiguration`: `* if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}` -> `arn:aws:lambda:us-east-1:111122223333:function:deploy-api if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}`, `arn:aws:lambda:us-east-1:111122223333:function:deploy-cron if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}`, `arn:aws:lambda:us-east-1:111122223333:function:deploy-worker if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}`
- **narrowed** `s3:GetObject`: `* if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}` -> `arn:aws:s3:::acme-artifacts/builds/* if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}`
- **narrowed** `s3:PutObject`: `* if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}` -> `arn:aws:s3:::acme-artifacts/builds/* if {"StringEquals":{"aws:RequestedRegion":["us-east-1","us-west-2"]}}`
- **removed** (200): `dynamodb:BatchGetItem`, `dynamodb:BatchWriteItem`, `dynamodb:ConditionCheckItem`, `dynamodb:CreateTable`, `dynamodb:DeleteItem`, `dynamodb:DeleteTable`, `dynamodb:DescribeStream`, `dynamodb:DescribeTable`, `dynamodb:DescribeTimeToLive`, `dynamodb:GetItem`, `dynamodb:GetRecords`, `dynamodb:GetShardIterator`, `dynamodb:ListStreams`, `dynamodb:ListTables`, `dynamodb:ListTagsOfResource`, `dynamodb:PutItem`, `dynamodb:Query`, `dynamodb:Scan`, `dynamodb:TagResource`, `dynamodb:UntagResource`, `dynamodb:UpdateItem`, `dynamodb:UpdateTable`, `dynamodb:UpdateTimeToLive`, `ec2:AttachVolume`, `ec2:AuthorizeSecurityGroupIngress`, `ec2:CreateSecurityGroup`, `ec2:CreateSnapshot`, `ec2:CreateTags`, `ec2:DeleteTags`, `ec2:DescribeImages`, `ec2:DescribeInstances`, `ec2:DescribeRegions`, `ec2:DescribeSecurityGroups`, `ec2:DescribeSnapshots`, `ec2:DescribeSubnets`, `ec2:DescribeVolumes`, `ec2:DescribeVpcs`, `ec2:DetachVolume`, `ec2:RebootInstances`, `ec2:RevokeSecurityGroupIngress`, +160 more

```diff
--- before
+++ after
@@ -2,10 +2,13 @@
   "Version": "2012-10-17",
   "Statement": [
     {
-      "Sid": "AdminInDeployRegions",
+      "Sid": "AllowLambda",
       "Effect": "Allow",
-      "Action": "*",
-      "Resource": "*",
+      "Action": [
+        "lambda:CreateFunction",
+        "lambda:DeleteFunction"
+      ],
+      "Resource": "arn:aws:lambda:us-east-1:111122223333:function:deploy-reports",
       "Condition": {
         "StringEquals": {
           "aws:RequestedRegion": [
@@ -16,10 +19,64 @@
       }
     },
     {
-      "Sid": "PassExecRoles",
+      "Sid": "AllowLambdaN2",
       "Effect": "Allow",
-      "Action": "iam:PassRole",
-      "Resource": "arn:aws:iam::111122223333:role/lambda-exec-*"
+      "Action": "lambda:GetFunction",
+      "Resource": [
+        "arn:aws:lambda:us-east-1:111122223333:function:deploy-api",
+        "arn:aws:lambda:us-east-1:111122223333:function:deploy-cron",
+        "arn:aws:lambda:us-east-1:111122223333:function:deploy-worker",
+        "arn:aws:lambda:us-west-2:111122223333:function:deploy-api",
+        "arn:aws:lambda:us-west-2:111122223333:function:deploy-cron",
+        "arn:aws:lambda:us-west-2:111122223333:function:deploy-worker"
+      ],
+      "Condition": {
+        "StringEquals": {
+          "aws:RequestedRegion": [
+            "us-east-1",
+            "us-west-2"
+          ]
+        }
+      }
+    },
+    {
+      "Sid": "AllowLambdaN3",
+      "Effect": "Allow",
+      "Action": [
+        "lambda:PublishVersion",
+        "lambda:UpdateFunctionCode",
+        "lambda:UpdateFunctionConfiguration"
+      ],
+      "Resource": [
+        "arn:aws:lambda:us-east-1:111122223333:function:deploy-api",
+        "arn:aws:lambda:us-east-1:111122223333:function:deploy-cron",
+        "arn:aws:lambda:us-east-1:111122223333:function:deploy-worker"
+      ],
+      "Condition": {
+        "StringEquals": {
+          "aws:RequestedRegion": [
+            "us-east-1",
+            "us-west-2"
+          ]
+        }
+      }
+    },
+    {
+      "Sid": "AllowS3",
+      "Effect": "Allow",
+      "Action": [
+        "s3:GetObject",
+        "s3:PutObject"
+      ],
+      "Resource": "arn:aws:s3:::acme-artifacts/builds/*",
+      "Condition": {
+        "StringEquals": {
+          "aws:RequestedRegion": [
+            "us-east-1",
+            "us-west-2"
+          ]
+        }
+      }
     }
   ]
 }
```
