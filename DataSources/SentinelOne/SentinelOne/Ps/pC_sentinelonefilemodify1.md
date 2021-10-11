#### Parser Content
```Java
{
Name = sentinelone-file-modify-1
  DataType = "file-write"
  Conditions = [ """"SentinelOne"""", """Deep Visibility Endpoint""", """fileModification {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}fileModification)""",
    """type"{1,20}:"{1,20}file"{1,20},"{1,20}name"{1,20}:"{1,20}({file_path}({file_parent}[^"]{1,2000}?)[\\\/]{0,2000}({file_name}[^\\\/"]{1,2000}?(\.({file_ext}[^\.\s"\\\/]{1,2000}))?))"""",
  ]
  DupFields = ["host->dest_host"]
}
```