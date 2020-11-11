#### Parser Content
```Java
{
Name = s-aws-cloudtrail-s3-activity
 Vendor = AWS
 Product = AWS CloudTrail
 Lms = Direct
 DataType = "cloud-storage-activity"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
 Conditions = ["""AwsApiCall""", """s3.amazonaws.com"""]
 Fields = [
            """"+eventTime"+\s*:\s*"+?(|({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z)"+\s*[,\]\}]""",
         """"+sourceIPAddress"+\s*:\s*"+?(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^"].+?))"+\s*[,\]\}]""",
         """"+eventSource"+\s*:\s*"+?(|({host}[^"].+?))"+\s*[,\]\}]""",
         """"userIdentity".+?"+invokedBy"+\s*:\s*"+?(|({dest_host}[^"].+?))"+\s*[,\]\}]""",
         """"+eventName"+\s*:\s*"+?(|({activity}[^"].+?))"+\s*[,\]\}]""",
         """"userIdentity".+?"+arn"+\s*:\s*"+?(|arn:aws:sts::\d+:([^"]+\/)+({identity}(?!\-\d+)[^\/]+?))"+\s*[,\]\}]""",
         """"userIdentity.+?type":"({identity_type}[^"]+)""",
         """"sessionIssuer.+?type":"({user_type}[^"]+)""",
         """"sessionIssuer.+?arn":".+?\/({user}[^"]+)"""
         """"+userName"+\s*:\s*"+?(|({user}[^"].+?))"+\s*[,\]\}]""",
         """"eventSource"\s*:\s*"(|({service}[^"]+))"""",
         """"bucketName"\s*:\s*"(|({bucket}[^"]+))"""",
         """"userAgent"\s*:\s*"(|({user_agent}[^"]+))"""",
         """"+errorCode"+\s*:\s*"+?(|({failure_code}[^"].+?))"+\s*[,\]\}]""",
         """"+errorMessage"+\s*:\s*"+?(|({failure_reason}[^"].+?))"+\s*[,\]\}]""",
         """"+accountId"+\s*:\s*"+?(|({account_id}[^"].+?))"+\s*[,\]\}]""",
         """"assumed-role\/({role}[^"]+)""",
         """"vpcEndpointId":"({vpc_id}[^"]+)""",
         """"awsRegion":"({region}[^"]+)""",
         """bytesTransferredOut":\s*({bytes_out}\d+(\.\d+)?)""",
         """bytesTransferredIn":\s*({bytes_in}\d+(\.\d+)?)""",
         """resources":.*?"ARN":\s+"({file_name}[^"]+)""",
 ]
}
```