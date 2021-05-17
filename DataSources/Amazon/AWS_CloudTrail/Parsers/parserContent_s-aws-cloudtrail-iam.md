#### Parser Content
```Java
{
Name = s-aws-cloudtrail-iam
 Vendor = Amazon
 Product = AWS CloudTrail
 Lms = Direct
 DataType = "cloud-admin-activity"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
 Conditions = ["""AwsApiCall""", """iam.amazonaws.com"""]
 Fields = [
     """"{1,20}eventTime"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z)"{1,20}\s{0,100}[,\]\}]""",
     """"{1,20}sourceIPAddress"{1,20}\s{0,100}:\s{0,100}"{1,20}?(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^"].+?))"{1,20}\s{0,100}[,\]\}]""",
     """"{1,20}eventSource"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({host}[^"].+?))"{1,20}\s{0,100}[,\]\}]""",
     """"{1,20}eventName"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({activity}[^"].+?))"{1,20}\s{0,100}[,\]\}]""",
     """"userIdentity"[^@]{1,2000}?"{1,20}arn"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|arn:aws:sts::\d{1,100}:([^"]{1,2000}\/){1,256}({identity}(?!\-\d{1,100})[^\/]{1,256}?))"{1,20}\s{0,100}[,\]\}]""",
     """"userIdentity[^@]{1,2000}?type":"({identity_type}[^"]{1,2000})""",
     """"sessionIssuer[^@]{1,2000}?type":"({user_type}[^"]{1,2000})""",
     """"sessionIssuer[^@]{1,2000}?arn":".+?\/({user}[^"]{1,2000})"""
     """"{1,20}userName"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({user}[^"]{1,2000}?))"{1,20}\s{0,100}[,\]\}]""",
     """({service}iam.amazonaws.com)""",
     """"policyArn.+?policy\/({policy}[^"]{1,2000})"""",
     """"roleName"\s{0,100}:\s{0,100}"(|({role}[^"]{1,2000}))"""",
     """"userAgent"\s{0,100}:\s{0,100}"(|({user_agent}[^"]{1,2000}))"""",
     """"{1,20}errorCode"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({failure_code}[^"]{1,2000}?))"{1,20}\s{0,100}[,\]\}]""",
     """"{1,20}errorMessage"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({failure_reason}[^"]{1,2000}?))"{1,20}\s{0,100}[,\]\}]""",
     """"{1,20}accountId"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({account_id}[^"]{1,2000}?))"{1,20}\s{0,100}[,\]\}]""",
     """"assumed-role\/({role}[^"]{1,2000})""",
     """"requestParameters[^@]{1,2000}?roleName":"({request_role_name}[^"]{1,2000})","policyName":"({request_policy_name}[^"]{1,2000})"""
     """"policyName":"({policy_name}[^"]{1,2000})"[^@]{1,2000}?policyDocument[^@]{1,2000}?Allow[^@]{1,2000}?Action[\\"\s:\[]{1,2000}[^"]{1,2000}"{1,20}({policy_action}[^"\\]{1,2000})""",
     """policyName"{1,20}:"{1,20}({policy_name}[^"]{1,2000})"{1,20}[^@]{1,2000}?policyDocument[^\}]{1,2000}?Resource[\\"\s:\[]{1,2000}[^"]{1,2000}"{1,20}({policy_resource}[^"\\]{1,2000})\\""""
     """"vpcEndpointId":"({vpc_id}[^"]{1,2000})""",
     """"awsRegion":"({region}[^"]{1,2000})""",
     """\srequestClientApplication=({app}[^\s]{1,2000})\s""",
 ]
}
```