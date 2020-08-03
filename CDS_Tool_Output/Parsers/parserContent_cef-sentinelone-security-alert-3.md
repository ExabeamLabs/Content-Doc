#### Parser Content
```Java
{
Name = cef-sentinelone-security-alert-3
  Product = SentinelOne
  DataType = "process-created"
  Conditions = [ """CEF:""", """|Security|SentinelOne|""", """|registry|""" ]
  Fields = ${SentinelOneParserTemplates.cef-sentinelone-security-alert.Fields}[
    """\sregistryPath:(|({object}.+?))(\s+\w+:|\s*$)""",
  ]
}
```