#### Parser Content
```Java
{
Name = sentinelone-task-register
  DataType = "windows-task-created"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """schedTaskRegister {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}schedTaskRegister)""",
    """\scommandLine:\s*"+(?:\\*)"+({command_line}[^"\\]+)""",
    """taskName:\s*"({task_name}[^"]+)"""
  ]
}
```