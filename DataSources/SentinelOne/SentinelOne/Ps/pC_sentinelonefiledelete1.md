#### Parser Content
```Java
{
Name = sentinelone-file-delete-1
  DataType = "file-delete"
  Conditions = [ """"SentinelOne"""", """Deep Visibility Endpoint""", """fileDeletion {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}fileDeletion)""",
    """type"{1,20}:"{1,20}file"{1,20},"{1,20}name"{1,20}:"{1,20}({file_path}({file_parent}[^"]{1,2000}?)[\\\/]{0,2000}({file_name}[^\\\/"]{1,2000}?(\.({file_ext}[^\.\s"\\\/]{1,2000}))?))"""",
  ]
  DupFields = ["host->dest_host"]
}
```