#### Parser Content
```Java
{
Name = cef-sentinelone-security-alert-5
  DataType = "web-activity"
  Conditions = [ """CEF:""", """|Security|SentinelOne|""", """|url|""" ]
  Fields = ${SentinelOneParserTemplates.cef-sentinelone-security-alert.Fields}[
    """\snetworkUrl:(|({malware_url}.+?))(\s+\w+:|\s*$)""",
    """\snetworkMethod:(|({method}.+?))(\s+\w+:|\s*$)""",
  ]
}
```