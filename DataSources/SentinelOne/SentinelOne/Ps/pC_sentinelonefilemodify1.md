#### Parser Content
```Java
{
Name = sentinelone-file-modify-1
  DataType = "file-write"
  Conditions = [ """"SentinelOne"""", """Deep Visibility Endpoint""", """fileModification {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}fileModification)""",
    """type"{1,20}:"{1,20}file"{1,20}
```