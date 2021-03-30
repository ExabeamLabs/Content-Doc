#### Parser Content
```Java
{
Name = s-aws-cloudtrail-activity-access-json
  Product = AWS CloudTrail
  DataType = "file-operations"
  Conditions = [  "\"AwsApiCall\"", "\"eventName\"", "\"awsRegion\"", "\"eventName\"", "\"HeadObject\"" ]
  Fields = ${AWSParserTemplates.s-aws-cloudtrail-activity-json.Fields} [
    """resources":.*?"ARN":\s+"({file_name}[^"]+)""",
  ]
  DupFields = [ "activity_action->event_code" ]
}
s-aws-cloudtrail-activity-json = {
  Vendor = AWS CloudTrail
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """"+eventTime"+\s*:\s*"+?(|({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)Z)"+\s*[,\]\}]""",
    """"+sourceIPAddress"+\s*:\s*"+?(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^"].+?))"+\s*[,\]\}]""",
    """"+eventSource"+\s*:\s*"+?(|({host}[^"].+?))"+\s*[,\]\}]""",
    """"userIdentity".+?"+invokedBy"+\s*:\s*"+?(|({dest_host}[^"].+?))"+\s*[,\]\}]""",
    """({app}AwsApiCall)""",
    """"+eventName"+\s*:\s*"+?(|({activity_action}[^"].+?))"+\s*[,\]\}]""",
    """"userIdentity".+?"+arn"+\s*:\s*"+?(|arn:aws:sts::\d+:([^"]+\/)+({user}(?!\-\d+)[^\/]+?))"+\s*[,\]\}]""",
    """"+userName"+\s*:\s*"+?(|({user}[^"].+?))"+\s*[,\]\}]""",
    """"eventSource"\s*:\s*"(|({object}[^"]+))"""",
    """"sessionIssuer"\s*:\s*.*?"arn"\s*:\s*"(?:|({object}[^"]+))"""",
    """"bucketName"\s*:\s*"(|({object}[^"]+))"""",
    """"policyArn"\s*:\s*"(|({object}[^"]+))"""",
    """"roleName"\s*:\s*"(|({object}[^"]+))"""",
    """"userAgent"\s*:\s*"(|({user_agent}[^"]+))"""",
    """"+errorCode"+\s*:\s*"+?(|({activity_outcome}[^"].+?))"+\s*[,\]\}]""",
    """"+errorMessage"+\s*:\s*"+?(|({additional_info}[^"].+?))"+\s*[,\]\}]""",
    """"+accountId"+\s*:\s*"+?(|({resource}[^"].+?))"+\s*[,\]\}]""",
    """ext_userIdentity_type=({account_type}.+?)\s*\w+=""",
    """requestParameters"+:.+?"+instanceId"+:"+({request_id}[^"]+)","attribute":"({request_action}[^"]+)"""",
  ]

```