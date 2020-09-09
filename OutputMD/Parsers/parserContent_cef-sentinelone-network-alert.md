#### Parser Content
```Java
{
Name = cef-sentinelone-network-alert
  Product = SentinelOne
  DataType = "dns-query"
  Conditions = [ """CEF:""", """|Security|SentinelOne|""", """|dns|""" ]
  Fields = ${SentinelOneParserTemplates.cef-sentinelone-security-alert.Fields}[
    """\sdnsRequest:(|({query}.+?))(\s+\w+:|\s*$)""",
    """\sdnsResponse:(|({response}.+?))(\s+\w+:|\s*$)""",
  ]
}
```