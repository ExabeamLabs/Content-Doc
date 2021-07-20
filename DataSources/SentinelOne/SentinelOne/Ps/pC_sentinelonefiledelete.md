#### Parser Content
```Java
{
Name = sentinelone-file-delete
  DataType = "file-delete"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """fileDeletion {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}fileDeletion)""",
    """\Wfname=({file_path}({file_parent}.*?)({file_name}[^\\.]{1,2000}(\.({file_ext}[^\\.]{1,2000}?))?))\s{1,100}(\w+=|$)""",
  ]
}
```