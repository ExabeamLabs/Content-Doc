#### Parser Content
```Java
{
Name = sentinelone-file-delete-1
  DataType = "file-delete"
  Conditions = [ """"SentinelOne"""", """Deep Visibility Endpoint""", """fileDeletion {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}fileDeletion)""",
    """type"{1,20}:"{1,20}file"{1,20}
```