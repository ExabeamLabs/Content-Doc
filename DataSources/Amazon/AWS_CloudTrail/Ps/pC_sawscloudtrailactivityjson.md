#### Parser Content
```Java
{
Name = s-aws-cloudtrail-activity-json
  Product = AWS CloudTrail
  DataType = "app-activity"
  Conditions = [  "\"AwsApiCall\"", "\"eventName\"", "\"awsRegion\"" ]

s-aws-cloudtrail-activity-json = {
  Vendor = Amazon
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """"{1,20}eventTime"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z?)"{1,20}\s{0,100}[,\]\}]""",
    """"{1,20}sourceIPAddress"{1,20}\s{0,100}:\s{0,100}"{1,20}?(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^"].+?))"{1,20}\s{0,100}[,\]\}]""",
    """"{1,20}eventSource"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({host}[^"].+?))"{1,20}\s{0,100}[,\]\}]""",
    """"userIdentity".+?"{1,20}invokedBy"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({dest_host}[^"].+?))"{1,20}\s{0,100}[,\]\}]""",
    """({app}AwsApiCall)""",
    """"{1,20}eventName"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({activity_action}[^"].+?))"{1,20}\s{0,100}[,\]\}]""",
    """"{1,20}eventName"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({activity}[^"].+?))"{1,20}\s{0,100}[,\]\}]""",
    """"{1,20}userName"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({user}[^"].+?))"{1,20}\s{0,100}[,\]\}]""",
    """"userIdentity".+?"arn"\s{0,100}:\s{0,100}"?(|arn:aws:sts::\d{1,100}:([^"]{1,2000}\/){1,256}({user}(?!\-\d{1,100})[^\/]{1,2000}?))(@[\w\.]{1,2000})?"\s{0,100}[,\]\}]""",
    """"eventSource"\s{0,100}:\s{0,100}"(|({service}[^"]{1,2000}))"""",
    """"sessionIssuer"\s{0,100}:\s{0,100}.*?"arn"\s{0,100}:\s{0,100}"(?:|({object}[^"]{1,2000}))"""",
    """"bucketName"\s{0,100}:\s{0,100}"(|({bucket}[^"]{1,2000}))"""",
    """"policyArn"\s{0,100}:\s{0,100}"(|({object}[^"]{1,2000}))"""",
    """"roleName"\s{0,100}:\s{0,100}"(|({object}[^"]{1,2000}))"""",
    """"userAgent"\s{0,100}:\s{0,100}"\[?(|({user_agent}[^"]{1,2000}?))\]?"""",
    """"{1,20}errorCode"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({activity_outcome}[^"].+?))"{1,20}\s{0,100}[,\]\}]""",
    """"{1,20}errorMessage"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({additional_info}[^"].+?))"{1,20}\s{0,100}[,\]\}]""",
    """"{1,20}accountId"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({resource}[^"].+?))"{1,20}\s{0,100}[,\]\}]""",
    """"requestParameters"\s{0,100}:[^\}]{1,2000}?"instanceId"\s{0,100}:\s{0,100}"({request_id}[^"]{1,2000})",("attribute"\s{0,100}:\s{0,100}"({request_action}[^"]{1,2000})")?""",
    """"awsRegion"\s{0,100}:\s{0,100}"({region}[^"]{1,2000})"""",
    """ext_userIdentity_type=({account_type}.+?)\s{0,100}\w+=""",
    """userIdentity.+?type":"({user_type}[^"]{1,2000})""",
    """assumed-role"[^:]{1,2000}?:role\/({role}[^"]{1,2000})""",
    """bytesTransferredOut":\s{0,100}({bytes_out}\d{1,100}(\.\d{1,100})?)"""
    """bytesTransferredIn":\s{0,100}({bytes_in}\d{1,100}(\.\d{1,100})?)""",
    """\srequestClientApplication=({app}[^\s]{1,2000})\s""",
    """items":\[[^\]]{1,2000}?fromPort":({src_port}\d{1,100}),""",
    """items":\[[^\]]{1,2000}?toPort":({dest_port}\d{1,100}),""",
    """items":\[[^\]]{1,2000}?ipProtocol":"({protocol}[^"]{1,2000})""""
  
}
```