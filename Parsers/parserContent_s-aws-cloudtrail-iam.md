#### Parser Content
```Java
{
Name = s-aws-cloudtrail-iam
 Vendor = AWS
 Product = AWS CloudTrail
 Lms = Direct
 DataType = "cloud-admin-activity"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
 Conditions = ["""AwsApiCall""", """iam.amazonaws.com"""]
 Fields = [
     """"+eventTime"+\s*:\s*"+?(|({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z)"+\s*[,\]\}]""",
     """"+sourceIPAddress"+\s*:\s*"+?(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^"].+?))"+\s*[,\]\}]""",
     """"+eventSource"+\s*:\s*"+?(|({host}[^"].+?))"+\s*[,\]\}]""",
     """"+eventName"+\s*:\s*"+?(|({activity}[^"].+?))"+\s*[,\]\}]""",
     """"userIdentity"[^@]+?"+arn"+\s*:\s*"+?(|arn:aws:sts::\d+:([^"]+\/)+({identity}(?!\-\d+)[^\/]+?))"+\s*[,\]\}]""",
     """"userIdentity[^@]+?type":"({identity_type}[^"]+)""",
     """"sessionIssuer[^@]+?type":"({user_type}[^"]+)""",
     """"sessionIssuer[^@]+?arn":".+?\/({user}[^"]+)"""
     """"+userName"+\s*:\s*"+?(|({user}[^"]+?))"+\s*[,\]\}]""",
     """({service}iam.amazonaws.com)""",
     """"policyArn.+?policy\/({policy}[^"]+)"""",
     """"roleName"\s*:\s*"(|({role}[^"]+))"""",
     """"userAgent"\s*:\s*"(|({user_agent}[^"]+))"""",
     """"+errorCode"+\s*:\s*"+?(|({failure_code}[^"]+?))"+\s*[,\]\}]""",
     """"+errorMessage"+\s*:\s*"+?(|({failure_reason}[^"]+?))"+\s*[,\]\}]""",
     """"+accountId"+\s*:\s*"+?(|({account_id}[^"]+?))"+\s*[,\]\}]""",
     """"assumed-role\/({role}[^"]+)""",
     """"requestParameters[^@]+?roleName":"({request_role_name}[^"]+)","policyName":"({request_policy_name}[^"]+)"""
     """"policyName":"({policy_name}[^"]+)"[^@]+?policyDocument[^@]+?Allow[^@]+?Action[\\"\s:\[]+[^"]+"+({policy_action}[^"\\]+)""",
     """policyName"+:"+({policy_name}[^"]+)"+[^@]+?policyDocument[^\}]+?Resource[\\"\s:\[]+[^"]+"+({policy_resource}[^"\\]+)\\""""
     """"vpcEndpointId":"({vpc_id}[^"]+)""",
     """"awsRegion":"({region}[^"]+)""",
     """\srequestClientApplication=({app}[^\s]+)\s""",
 ]
}
```