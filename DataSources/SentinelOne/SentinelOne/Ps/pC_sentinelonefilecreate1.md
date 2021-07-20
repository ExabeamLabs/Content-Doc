#### Parser Content
```Java
{
Name = sentinelone-file-create-1
  DataType = "file-write"
  Conditions = [ """"SentinelOne"""", """Deep Visibility Endpoint""", """fileCreation {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """type"{1,20}:"{1,20}file"{1,20}
```