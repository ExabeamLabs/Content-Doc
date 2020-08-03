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
    """"sessionIssuer"\s*:\s*.*?"arn":"[^"]*?role/({role}[^"\\\/]+)""",
    """requestParameters"+:.+?"+instanceId"+:"+({request_id}[^"]+)","attribute":"({request_action}[^"]+)"""",
  ]
  DupFields = [ "role->additional_info", "host->object" ]
}
```