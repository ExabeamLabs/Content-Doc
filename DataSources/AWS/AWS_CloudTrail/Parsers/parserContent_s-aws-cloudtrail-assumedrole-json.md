#### Parser Content
```Java
{
Name = s-aws-cloudtrail-assumedrole-json
  Conditions = [  "\"AwsApiCall\"", "\"eventName\"", "\"awsRegion\"", "type=AssumedRole" ]
  Fields = ${AWSParserTemplates.s-aws-cloudtrail-activity-json.Fields}[
    """\Wsuser=[^=]*?({user}[^\\\/@=]+)@[^=]+?(\s+\w+=|\s*$)""",
    """\Wext_userIdentity_sessionContext_sessionIssuer_type=(|({activity}.+?))(\s+\w+=|\s*$)""",
    """\WflexString1=(|({activity}.+?))(\s+\w+=|\s*$)""",
    """"+userName"+\s*:\s*"+?(|({target}[^"].+?))"+\s*[,\]\}]""",
    """"sessionIssuer"\s*:\s*.*?"arn":"[^"]*?role/({role}[^"\\\/]+)""",
  ]
  DupFields = [ "role->additional_info", "host->object" ]
}
```