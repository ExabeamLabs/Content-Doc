#### Parser Content
```Java
{
Name = sentinelone-process-created-1
  DataType = "process-created"
  Conditions = [ """"SentinelOne"""", """Deep Visibility Endpoint""", """processCreation {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}processCreation)""",
    """commandLine:\s{0,100}\\?["\\]{0,2000}"{1,20}({command_line}[^"]{1,2000}?)\\*"""",
  ]
}
```