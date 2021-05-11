#### Parser Content
```Java
{
Name = sentinelone-file-modify
  DataType = "file-write"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """fileModification {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}fileModification)""",
    """\spath:\s{0,100}"{1,20}({file_path}(({file_parent}\w+:[^"].+?)\\+)?({file_name}[^\\.]+\.({file_ext}[^"\\,:]+)))"""",
  ]
}
```