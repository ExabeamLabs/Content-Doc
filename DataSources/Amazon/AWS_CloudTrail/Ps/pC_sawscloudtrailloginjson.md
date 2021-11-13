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
    """"{1,20}userName"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({user}[^"].+?))"{1,20}\s{0,100}[,\]\}]""",
    """"userIdentity\\?".+?"arn\\?"\s{0,100}:\s{0,100}\\?"?(|arn:aws:sts::\d{1,100}:([^"]{1,2000}\/){1,256}({user}(?!\-\d{1,100})[^\/]{1,2000}?))(@[\w\.]{1,2000})?\\?"\s{0,100}[,\]\}]""",
    """"errorMessage"\s{0,100}:\s{0,100}"({failure_reason}[^"]{1,2000})"""",
    """"responseElements\\?"\s{0,100}:\s{0,100}.+?\s{0,100}\\?".+?\\?"\s{0,100}:\s{0,100}\\?"({outcome}[^"]{1,2000}?)\\?"""",
    """"eventType"{1,20}\s{0,100}:\s{0,100}"({app}[^"]{1,2000})""""
    """"userAgent"{1,20}\s{0,100}:\s{0,100}"({user_agent}[^"]{1,2000})"""",
    """"recipientAccountId"{1,20}\s{0,100}:\s{0,100}"({object}[^"]{1,2000})""""
    """"awsRegion":"({region}[^"]{1,2000})"""",
    """\srequestClientApplication=({app}[^\s]{1,2000})\s""",
  ]


}
```