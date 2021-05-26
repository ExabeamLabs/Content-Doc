#### Parser Content
```Java
{
Name = sentinelone-task-register
  DataType = "windows-task-created"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """schedTaskRegister {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}schedTaskRegister)""",
    """\scommandLine:\s{0,100}"{1,20}(?:\\*)"{1,20}({command_line}[^"\\]{1,2000})""",
    """taskName:\s{0,100}"({task_name}[^"]{1,2000})"""
  ]
}
```