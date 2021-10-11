#### Parser Content
```Java
{
Name = sentinelone-file-create-1
  DataType = "file-write"
  Conditions = [ """"SentinelOne"""", """Deep Visibility Endpoint""", """fileCreation {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """type"{1,20}:"{1,20}file"{1,20},"{1,20}name"{1,20}:"{1,20}({file_path}({file_parent}[^"]{1,2000}?)[\\\/]{0,2000}({file_name}[^\\\/"]{1,2000}?(\.({file_ext}[^\.\s"\\\/]{1,2000}))?))"""",
    """({event_name}fileCreation)""",
  ]
  DupFields = ["host->dest_host"]
}
```