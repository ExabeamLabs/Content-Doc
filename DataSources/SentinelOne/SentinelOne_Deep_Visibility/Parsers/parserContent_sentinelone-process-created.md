#### Parser Content
```Java
{
Name = sentinelone-process-created
  DataType = "process-created"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """processCreation""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}processCreation)""",
    """\scommandLine:\s*"+(?:\\*)"+({command_line}[^"\\]+)""",
  ]
}
```