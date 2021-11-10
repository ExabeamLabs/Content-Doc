#### Parser Content
```Java
{
Name = sentinelone-task-update-2
  DataType = "windows-task-created"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """taskName""", """schedTaskStart {"""]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """\scommandLine:\s{0,100}"{1,20}({command_line}[^\n]{1,2000}?)\s{0,100}"(\\n)?\s{1,100}\w{1,100}""",
    """\spath:\s{0,100}"{1,20}({file_path}(({file_parent}\w{1,100}:[^"]{1,2000}?)\\{1,20})?({file_name}[^\\.]{1,2000}\.({file_ext}[^"\\,:]{1,2000})))"""",
    """taskName:\s{0,100}"({task_name}[^"]{1,2000})""""
  ]
  DupFields = ["host->dest_host"]
}
}
```