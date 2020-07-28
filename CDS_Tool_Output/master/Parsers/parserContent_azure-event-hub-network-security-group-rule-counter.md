#### Parser Content
```Java
{
Name = azure-event-hub-network-security-group-rule-counter
  DataType = "network-connection"
  Conditions = ["""ext_category=NetworkSecurityGroupRuleCounter""" ]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
     """\WrequestClientApplication=(|({app}.+?))(\s+\w+=|\s*$)""",
    """category":"({activity}.*?[^\\])"""",
    """type":"({outcome}.*?[^\\])"""",
    """rule":"({ruleName}.*?[^\\])"""",
    """primaryIPv4Address":"({src_ip}.*?[^\\])"""",
    """ruleName":"({rule}.*?[^\\])"""",
    """direction":"({direction}.*?[^\\])"""",
  ]
}
```