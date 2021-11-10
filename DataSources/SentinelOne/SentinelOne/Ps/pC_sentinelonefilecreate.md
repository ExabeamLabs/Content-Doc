#### Parser Content
```Java
{
Name = sentinelone-file-create
  DataType = "file-write"
  Conditions = [ """CEF:""", """dproc=Deep Visibility Endpoint""", """destinationServiceName=SentinelOne""", """fileCreation {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}fileCreation)""",
    """\Wfname=({file_path}({file_parent}[^=]{0,2000}?)({file_name}[^\\]{1,2000}?(\.({file_ext}[^\\.]{1,2000}?))?))\s{1,100}(\w{1,100}=|$)""",
  ]
  DupFields = ["host->dest_host"]
}
}
```