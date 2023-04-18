#### Parser Content
```Java
{
Name = aws-putbucketpolicy-json
  Vendor = Amazon
  Product = AWS CloudTrail
  Lms = Direct
  DataType = "aws-bucket-policy"
  TimeFormat = """yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"""
  Conditions = [ """AwsApiCall""", """"eventName":"PutBucketPolicy"""" ] 
  Fields = ${AwsParserTemplates.aws-cloudtrail-json.Fields}[
    """"{1,20}Sid\\?":\s{0,100}\{?\[?({policy_sids}[^\]\}]+)\]?\}?Effect"""",
    """"{1,20}bucketPolicy\\{0,20}"{1,20}:\s{0,10}\{[^\[]+({policy_content}"{1,20}Statement\\{0,20}"{1,20}[^\]]+\])""",
    """"{1,20}Effect\\?":\s{0,100}\\?"Allow\\?".+?Principal\\?":\s{0,100}\{?\[?({allowed_users}[^\]\}]+)\]?\}?"Action?""",
    """"{1,20}Effect\\?":\s{0,100}\\?"Allow\\?".+?Action\\?":\s{0,100}\[?({allowed_permissions}[^\.\]\}]+)\]?.{0,10}"Resource?""",
    """"{1,20}Effect\\?":\s{0,100}\\?"Allow\\?".+?Resource\\?":\s{0,100}\{?\[?({allowed_resources}[^\]\}]+)\]?\}?""",
    """"{1,20}Effect\\?":\s{0,100}\\?"Allow\\?".+?Condition\\?":\s{0,100}\[?({allowed_conditions}[^\.\]\}]+)\]?"""",
    """"{1,20}Effect\\?":\s{0,100}\\?"Deny\\?".+?Principal\\?":\s{0,100}\{?\[?({denied_users}[^\]\}]+)\]?\}?"Action?""",
    """"{1,20}Effect\\?":\s{0,100}\\?"Deny\\?".+?Action\\?":\s{0,100}\[?({denied_permissions}[^\.\]\}]+)\]?.{0,10}"Resource?""",
    """"{1,20}Effect\\?":\s{0,100}\\?"Deny\\?".+?Resource\\?":\s{0,100}\{?\[?({denied_resources}[^\]\}]+)\]?\}?""",
    """"{1,20}requestParameters.+?bucketName\\?":\s{0,100}\\?"({bucket_name}[^"]{1,2000}?)\\?"""",
    """"{1,20}requestParameters.+?Host\\?":\s{0,100}\\?"({bucket_host}[^"]{1,2000}?)\\?"""",
    """"{1,20}resources.+?(?:ARN|arn)\\?":\s{0,100}\\?"({bucket_arn}[^"]{1,2000}?)\\?"""",
  ]
  DupFields = ["bucket_name->bucket"]

aws-cloudtrail-json = {
    Vendor = Amazon
    Product = AWS CloudTrail
    Lms = Direct
    DataType = "aws-general-activity"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S{1,2000})""",
      """"userIdentity":\{("[^,]+,){0,10}"type"\\?:\s{0,100}\\?"({user_type}[^"]{1,2000}?)\\?"""",
      """"userIdentity":\{("[^,]+,){0,10}"type"\\?:\s{0,100}\\?"({user}Root)\\?"""",
      """"userIdentity":\{("[^,]+,){0,10}"arn"\\?:\s{0,100}\\?"({user_arn}[^"]{1,2000}?)\\?"""",
      """"userIdentity":\{("[^,]+,){0,10}"accountId\\?"{1,20}\s{0,100}:\s{0,100}\\?"{1,20}?({aws_account}[^"]{1,2000}?)\\?"{1,20}\s{0,100}[,\]\}]""",
     """"userIdentity":\{("[^,]+,){0,10}"principalId\\?"{1,20}\s{0,100}:\s{0,100}\\?"{1,20}?({principal_id}[^"]{1,2000}?)\\?"{1,20}\s{0,100}[,\]\}]""",
      """"userName"\\?:\s{0,100}\\?"({user}[^"]{1,2000}@({domain}[^@"]{1,2000})|[^"]{1,2000})\\?"""",
      """"userIdentity":\{("[^,]+,){0,10}"attributes":\{("[^,]+,){0,10}"mfaAuthenticated"\\?:\s{0,100}\\?"({mfa}[^"]{1,2000}?)\\?"""",
      """"assumedRoleUser":\{("[^,]+,){0,10}"arn"\s{0,100}:\s{0,100}"({assumed_role_arn}[^"]{1,2000})\\?""""
      """"eventTime"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z?)"{1,20}\s{0,100}[,\]\}]""",
      """"eventSource"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({service}[^"]{1,2000}))"{1,20}\s{0,100}[,\]\}]""",
      """"eventName"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({operation}[^"]{1,2000}))"{1,20}\s{0,100}[,\]\}]""",
      """"awsRegion"\s{0,100}:\s{0,100}"({region}[^"]{1,2000})"""",
      """"sourceIPAddress"{1,20}\s{0,100}:\s{0,100}"{1,20}?(?:({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^"]{1,2000}))"{1,20}\s{0,100}[,\]\}]""",
      """"userAgent"\s{0,100}:\s{0,100}"\[?\s{0,100}(|({user_agent}[^"]{1,2000}?))\]?"""",
      """"eventID\\?"{1,20}:\\?"{1,20}({event_code}[^"\\]{1,2000})\\?"""",
      """"eventType"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({log_type}[^"]{1,2000}))"{1,20}\s{0,100}[,\]\}]""",
      """"errorCode"\s{0,100}:\s{0,100}"({result_code}[^"]{1,2000})"""",
      """"errorMessage"\s{0,100}:\s{0,100}"({failure_reason}[^"]{1,2000})"""",
      """"readOnly"\s{0,100}:\s{0,100}({readonly}[^",]{1,2000})""",
      """"vpcEndpointId":"({vpc}[^"]{1,2000})""",
    
}
```