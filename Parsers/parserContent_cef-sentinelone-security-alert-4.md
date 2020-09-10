#### Parser Content
```Java
{
Name = cef-sentinelone-security-alert-4
  Product = SentinelOne
  DataType = "process-created"
  Conditions = [ """CEF:""", """|Security|SentinelOne|""", """|scheduled_task|""" ]
  Fields = ${SentinelOneParserTemplates.cef-sentinelone-security-alert.Fields}[
    """\staskName:(|({object}.+?))(\s+\w+:|\s*$)""",
  ]
}
```