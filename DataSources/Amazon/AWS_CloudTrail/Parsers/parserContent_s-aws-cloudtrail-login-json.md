#### Parser Content
```Java
{
Name = s-aws-cloudtrail-login-json
  Vendor = Amazon
  Product = AWS CloudTrail
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""AwsConsoleSignIn""", """eventName"""]
  Fields = [
    """"{1,20}eventTime"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z)"{1,20}\s{0,100}[,\]\}]""",
    """"{1,20}sourceIPAddress"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({src_ip}[^"].+?))"{1,20}\s{0,100}[,\]\}]""",
    """"{1,20}eventName"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({activity_action}[^"].+?))"{1,20}\s{0,100}[,\]\}]""",
    """"{1,20}eventSource"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({host}[^"].+?))"{1,20}\s{0,100}[,\]\}]""",
    """"userIdentity"[^@]+?"{1,20}arn"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|arn:aws:(sts|iam)::\d{1,100}:([^"]+\/){0,256}(({user_email}\w+@\w+\.\w+)|({user}(?!\-\d{1,100})[^\/]+?)))"{1,20}\s{0,100}[,\]\}]""",
    """"{1,20}userName"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({user}[^"].+?))"{1,20}\s{0,100}[,\]\}]""",
    """"errorMessage"\s{0,100}:\s{0,100}"({failure_reason}[^"]+)"""",
    """"responseElements"\s{0,100}:\s{0,100}.+?\s{0,100}".+?"\s{0,100}:\s{0,100}"({outcome}[^"]+)"""",
    """"eventType"{1,20}\s{0,100}:\s{0,100}"({app}[^"]+)""""
    """"userAgent"{1,20}\s{0,100}:\s{0,100}"({user_agent}[^"]+)"""",
    """"recipientAccountId"{1,20}\s{0,100}:\s{0,100}"({object}[^"]+)""""
    """"awsRegion":"({region}[^"]+)"""",
    """\srequestClientApplication=({app}[^\s]+)\s""",
  ]
}
```