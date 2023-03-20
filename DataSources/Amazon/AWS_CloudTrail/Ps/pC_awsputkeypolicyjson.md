#### Parser Content
```Java
{
Name = aws-putkeypolicy-json
  Vendor = Amazon
  Product = AWS CloudTrail
  Lms = Direct
  DataType = "aws-key-policy"
  TimeFormat = """yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"""
  Conditions = [ """AwsApiCall""", """"eventName":"PutKeyPolicy"""" ] 
  Fields = ${AwsParserTemplates.aws-cloudtrail-json.Fields}[
    """"{1,20}requestParameters.+?keyId\\?":\s{0,100}\\?"({key_id}[^"]{1,2000}?)\\?"""",
    """"{1,20}requestParameters.+?policyName\\?":\s{0,100}\\?"({policy}[^"]{1,2000}?)\\?"""",
    """"{1,20}[Aa]llow\s{1,20}[Aa]ccess\s{1,20}[Ff]or\s{1,20}[Kk]ey\s{1,20}[Aa]dministrators\\?".+?"{1,20}Effect\\?":\s{0,100}\\?"Allow\\?".+?Principal\\?":\s{0,100}\[?\{?({allowed_admins}[^\]\}]+)\]?"""",
    """"{1,20}[Aa]llow\s{1,20}[Uu]se\s{1,20}[Oo]f\s{1,20}[Tt]he\s{1,20}[Kk]ey\\?".+?"{1,20}Effect\\?":\s{0,100}\\?"Allow\\?".+?Principal\\?":\s{0,100}\[?\{?({allowed_users}[^\]\}]+)\]?"""",
  ]

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
     """\Wsuser=[^=]{0,2000}?(({user_email}[^@=\s\/:]{1,2000}@[^=\.\s\/:]{1,2000}\.[^\s=\/:]{1,2000}?)|({user}[^\\\/@=]{1,2000})@[^=]{1,2000}?)(\s{1,100}\w+=|\s{0,100}$)""",
      """"userName"\\?:\s{0,100}\\?"(({user_email}[^"@]{1,2000}@[^"\.]{1,2000}\.[^"]{1,2000})|({user}[^"]{1,2000})(@({domain}[^@"]{1,2000}))?)\\?"""",
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
      """"readOnly"\s{0,100}:\s{0,100}({readonly}[^",\}]{1,2000})("|,|\}\s{0,20}$)""",
      """"vpcEndpointId":"({vpc}[^"]{1,2000})""",
    
}
```