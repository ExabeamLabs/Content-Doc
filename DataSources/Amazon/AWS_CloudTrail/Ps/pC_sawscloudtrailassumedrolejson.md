#### Parser Content
```Java
{
Name = s-aws-cloudtrail-assumedrole-json
  Product = AWS CloudTrail
  DataType = "app-activity"
  Conditions = [  "\"AwsApiCall\"", "\"eventName\"", "\"awsRegion\"", "type=AssumedRole" ]
  Fields = ${AWSParserTemplates.s-aws-cloudtrail-activity-json.Fields}[
    """\Wsuser=[^=]{0,2000}?({user}[^\\\/@=]{1,2000})@[^=]{1,2000}?(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wext_userIdentity_sessionContext_sessionIssuer_type=(|({activity}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WflexString1=(|({activity}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"{1,20}userName"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({target}[^"].+?))"{1,20}\s{0,100}[,\]\}]""",
    """"requestParameters":\{"userName":"({target}[^"]{1,2000})"\},""",
    """"sessionIssuer"\s{0,100}:\s{0,100}[^@]{0,2000}?"arn":"[^"]{0,2000}?role/({role}[^"\\\/]{1,2000})""",
    """"UserId":\s"({user_email}[^@]{1,2000}@({email_domain}[^"]{1,2000}))"""
    """requestParameters"{1,20}:.+?"{1,20}instanceId"{1,20}:"{1,20}({request_id}[^"]{1,2000})","attribute":"({request_action}[^"]{1,2000})"""",
    """\sresource:\s{1,100}({additional_info}[^\s"]{1,2000})(\s|")""",
    """"responseElements":[^@]{1,2000}?"name":"({object_name}[^"]{1,2000})"""",
    """"responseElements":[^@]{1,2000}?"s3BucketName":"({object}[^"]{1,2000})"""",
    """"responseElements":[^@]{1,2000}?"s3KeyPrefix":"({object_key_prefix}[^"]{1,2000})"""",
    """"responseElements":[^@]{1,2000}?"snsTopicName":"({sns_topic_name}[^"]{1,2000})"""",
    """"awsRegion":"({region}[^"]{1,2000})"""",
    """\srequestClientApplication=({app}[^\s]{1,2000})\s""",
    """"policyName":"({policy}[^"]{1,2000})"""",
    """"configRuleName":"({rule_name}[^"]{1,2000})"""",
  ]
}
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
    """"userIdentity\\?".+?"arn\\?"\s{0,100}:\s{0,100}\\?"?(|arn:aws:sts::\d{1,100}:[^\/]{1,2000}\/({user}[^"]{1,2000})\/{1,256}(?!\-\d{1,100})[^\/]{1,2000}?)(@[\w\.]{1,2000})?\\?"\s{0,100}[,\]\}]""",
    """"{1,20}userName"{1,20}\s{0,100}:\s{0,100}"{1,20}?(|({user}[^"].+?))"{1,20}\s{0,100}[,\]\}]""",
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
    """userIdentity.+?type\\?":\s{0,100}\\?"({user_type}[^"]{1,2000}?)\\?"""",
    """assumed-role"[^:]{1,2000}?:role\/({role}[^"]{1,2000})""",
    """bytesTransferredOut":\s{0,100}({bytes_out}\d{1,100}(\.\d{1,100})?)"""
    """bytesTransferredIn":\s{0,100}({bytes_in}\d{1,100}(\.\d{1,100})?)""",
    """\srequestClientApplication=({app}[^\s]{1,2000})\s""",
    """items":\[[^\]]{1,2000}?fromPort":({src_port}\d{1,100}),""",
    """items":\[[^\]]{1,2000}?toPort":({dest_port}\d{1,100}),""",
    """items":\[[^\]]{1,2000}?ipProtocol":"({protocol}[^"]{1,2000})""""
  ]
}
```