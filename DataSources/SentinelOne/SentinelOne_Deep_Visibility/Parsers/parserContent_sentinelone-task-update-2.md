#### Parser Content
```Java
{
Name = sentinelone-task-update-2
  DataType = "windows-task-created"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """taskName""", """schedTaskStart {"""]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """\scommandLine:\s*"+(?:\\*)"+({command_line}[^"]+)""",
    """\spath:\s*"+({file_path}(({file_parent}\w+:[^"].+?)\\+)?({file_name}[^\\.]+\.({file_ext}[^"\\,:]+)))"""",
  ]
}
```