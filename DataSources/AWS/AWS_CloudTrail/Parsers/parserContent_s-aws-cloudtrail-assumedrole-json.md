#### Parser Content
```Java
{
Name = s-aws-cloudtrail-assumedrole-json
  Product = AWS CloudTrail
  DataType = "app-activity"
  Conditions = [  "\"AwsApiCall\"", "\"eventName\"", "\"awsRegion\"", "type=AssumedRole" ]
  Fields = ${AWSParserTemplates.s-aws-cloudtrail-activity-json.Fields}[
    """\Wsuser=[^=]*?({user}[^\\\/@=]+)@[^=]+?(\s+\w+=|\s*$)""",
    """\Wext_userIdentity_sessionContext_sessionIssuer_type=(|({activity}.+?))(\s+\w+=|\s*$)""",
    """\WflexString1=(|({activity}.+?))(\s+\w+=|\s*$)""",
    """"+userName"+\s*:\s*"+?(|({target}[^"].+?))"+\s*[,\]\}]""",
    """"requestParameters":\{"userName":"({target}[^"]+)"\}
s-aws-cloudtrail-activity-json = {
  Vendor = Amazon
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """"+eventTime"+\s*:\s*"+?(|({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z)"+\s*[,\]\}]""",
    """"+sourceIPAddress"+\s*:\s*"+?(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^"].+?))"+\s*[,\]\}]""",
    """"+eventSource"+\s*:\s*"+?(|({host}[^"].+?))"+\s*[,\]\}]""",
    """"userIdentity".+?"+invokedBy"+\s*:\s*"+?(|({dest_host}[^"].+?))"+\s*[,\]\}]""",
    """({app}AwsApiCall)""",
    """"+eventName"+\s*:\s*"+?(|({activity_action}[^"].+?))"+\s*[,\]\}]""",
    """"+eventName"+\s*:\s*"+?(|({activity}[^"].+?))"+\s*[,\]\}]""",
    """"+userName"+\s*:\s*"+?(|({user}[^"].+?))"+\s*[,\]\}]""",
    """"userIdentity".+?"arn"\s*:\s*"?(|arn:aws:sts::\d+:([^"]+\/)+({user}(?!\-\d+)[^\/]+?))(@[\w\.]+)?"\s*[,\]\}]""",
    """"eventSource"\s*:\s*"(|({service}[^"]+))"""",
    """"sessionIssuer"\s*:\s*.*?"arn"\s*:\s*"(?:|({object}[^"]+))"""",
    """"bucketName"\s*:\s*"(|({bucket}[^"]+))"""",
    """"policyArn"\s*:\s*"(|({object}[^"]+))"""",
    """"roleName"\s*:\s*"(|({object}[^"]+))"""",
    """"userAgent"\s*:\s*"\[?(|({user_agent}[^"]+?))\]?"""",
    """"+errorCode"+\s*:\s*"+?(|({activity_outcome}[^"].+?))"+\s*[,\]\}]""",
    """"+errorMessage"+\s*:\s*"+?(|({additional_info}[^"].+?))"+\s*[,\]\}]""",
    """"+accountId"+\s*:\s*"+?(|({resource}[^"].+?))"+\s*[,\]\}]""",
    """"requestParameters"\s*:[^\}]+?"instanceId"\s*:\s*"({request_id}[^"]+)",("attribute"\s*:\s*"({request_action}[^"]+)")?""",
    """"awsRegion"\s*:\s*"({region}[^"]+)"""",
    """ext_userIdentity_type=({account_type}.+?)\s*\w+=""",
    """userIdentity.+?type":"({user_type}[^"]+)""",
    """assumed-role"[^:]+?:role\/({role}[^"]+)""",
    """bytesTransferredOut":\s*({bytes_out}\d+(\.\d+)?)"""
    """bytesTransferredIn":\s*({bytes_in}\d+(\.\d+)?)""",
    """\srequestClientApplication=({app}[^\s]+)\s""",
  ]

```