#### Parser Content
```Java
{
Name = aws-updatefunctionconfiguration-json
  Vendor = Amazon
  Product = AWS CloudTrail
  Lms = Direct
  DataType = "aws-function-write"
  TimeFormat = """yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"""
  Conditions = [ """AwsApiCall""", """"eventName":"UpdateFunctionConfiguration""" ] 
  Fields = ${AwsParserTemplates.aws-cloudtrail-json.Fields}[
    """"{1,20}requestParameters.+?functionName\\?":\s{0,100}\\?"({function_name}[^"]{1,2000}?)\\?"""",
    """"{1,20}responseElements.+?functionArn\\?":\s{0,100}\\?"({function_arn}[^"]{1,2000}?)\\?"""",
    """"{1,20}responseElements.+?runtime\\?":\s{0,100}\\?"({function_runtime}[^"]{1,2000}?)\\?"""",
    """"{1,20}responseElements.+?role\\?":\s{0,100}\\?"({function_role}[^"]{1,2000}?)\\?"""",
    """"{1,20}responseElements.+?codeSize\\?":\s{0,100}\\?({code_size}[^,"]{1,2000})\\?""",
    """"{1,20}responseElements.+?codeSha256\\?":\s{0,100}\\?"({code_sha256}[^"]{1,2000}?)\\?"""",
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
      """"userIdentity".{1,2000}?"type":"(user|User|IAMUser)".{1,2000}?"userName"\\?:\s{0,100}\\?"(({user_email}[^"@]{1,2000}@[^"\.]{1,2000}\.[^"]{1,2000})|({user}[^"]{1,2000})(@({domain}[^@"]{1,2000}))?)\\?"""",
      """"userIdentity\\?".+?"arn\\?"\s{0,100}:\s{0,100}\\?"?arn:aws:sts::\d{1,100}:assumed-role\/([^\/"]{1,2000}\/)(({user_email}[^\@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})|({user}[^"]{1,2000}))"""
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