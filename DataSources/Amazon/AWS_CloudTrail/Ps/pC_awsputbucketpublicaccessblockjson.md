#### Parser Content
```Java
{
Name = aws-putbucketpublicaccessblock-json
  Vendor = Amazon
  Product = AWS CloudTrail
  Lms = Direct
  DataType = "aws-bucket-putaccessblock"
  TimeFormat = """yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"""
  Conditions = [ """AwsApiCall""", """"eventName":"PutBucketPublicAccessBlock"""" ] 
  Fields = ${AwsParserTemplates.aws-cloudtrail-json.Fields}[
    """"{1,20}requestParameters.+?bucketName\\?":\s{0,100}\\?"({bucket_name}[^"]{1,2000}?)\\?"""",
    """"{1,20}requestParameters.+?RestrictPublicBuckets\\?":\s{0,100}\\?({restrict_public_buckets}[^",]{1,2000}?),""",
    """"{1,20}requestParameters.+?BlockPublicPolicy\\?":\s{0,100}\\?({block_public_policy}[^",]{1,2000}?),""",
    """"{1,20}requestParameters.+?BlockPublicAcls\\?":\s{0,100}\\?({block_public_acls}[^",]{1,2000}?),""",
    """"{1,20}requestParameters.+?IgnorePublicAcls\\?":\s{0,100}\\?({ignore_public_acls}[^",]{1,2000}?),""",
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