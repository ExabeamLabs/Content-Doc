#### Parser Content
```Java
{
Name = sentinelone-file-delete
  DataType = "file-delete"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """fileDeletion""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}fileDeletion)""",
    """\Wfname=({file_path}({file_parent}.*?)({file_name}[^\\.]+(\.({file_ext}[^\\.]+?))?))\s+(\w+=|$)""",
  ]
}
```