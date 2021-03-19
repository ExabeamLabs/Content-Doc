#### Parser Content
```Java
{
Name = sentinelone-task-update
  DataType = "windows-task-created"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """schedTaskUpdate {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}schedTaskUpdate)""",
    """\scommandLine:\s*"+(?:\\*)"+({command_line}[^"\\]+)""",
    """taskName:\s*"({task_name}[^"]+)"""
  ]
}
```