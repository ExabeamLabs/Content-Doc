#### Parser Content
```Java
{
Name = s-aws-cloudtrail-login-json
  Vendor = AWS
  Product = AWS CloudTrail
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""AwsConsoleSignIn""", """eventName"""]
  Fields = [
    """"+eventTime"+\s*:\s*"+?(|({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z)"+\s*[,\]\}]""",
    """"+sourceIPAddress"+\s*:\s*"+?(|({src_ip}[^"].+?))"+\s*[,\]\}]""",
    """"+eventName"+\s*:\s*"+?(|({activity_action}[^"].+?))"+\s*[,\]\}]""",
    """"+eventSource"+\s*:\s*"+?(|({host}[^"].+?))"+\s*[,\]\}]""",
    """"userIdentity".+?"+arn"+\s*:\s*"+?(|arn:aws:(sts|iam)::\d+:([^"]+\/)*(({user_email}\w+@\w+\.\w+)|({user}(?!\-\d+)[^\/]+?)))"+\s*[,\]\}]""",
    """"+userName"+\s*:\s*"+?(|({user}[^"].+?))"+\s*[,\]\}]""",
    """"errorMessage"\s*:\s*"({failure_reason}[^"]+)"""",
    """"responseElements"\s*:\s*.+?\s*".+?"\s*:\s*"({outcome}[^"]+)"""",
    """"eventType"+\s*:\s*"({app}[^"]+)""""
    """"userAgent"+\s*:\s*"({user_agent}[^"]+)"""",
    """"recipientAccountId"+\s*:\s*"({object}[^"]+)""""
    """"awsRegion":"({region}[^"]+)"""",
  ]
}

{
  Name = ccure-app-activity
  Vendor = CCURE
  Product = CCURE
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss a"
  Conditions = [ """<CCure App Activity Conditions>""" ]
  Fields = [
              """exabeam_raw=({activity}[^,]+)""",
              """exabeam_raw=[^,]*,({user}[^,]+)""",
              """exabeam_raw=([^,]*,){2}({object}.+?)\s+\('""",
              """exabeam_raw=.+?\('({additional_info}[^']+)""",
              """exabeam_host=({host}[^\s]+)""",
              """({time}\d\d\d\d\-\d\d\-\d\d \d+:\d+:\d+ (am|AM|PM|pm))"""
	]
}
```