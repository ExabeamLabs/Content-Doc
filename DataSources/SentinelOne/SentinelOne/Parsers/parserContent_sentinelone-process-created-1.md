#### Parser Content
```Java
{
Name = sentinelone-process-created-1
  DataType = "process-created"
  Conditions = [ """"SentinelOne"""", """Deep Visibility Endpoint""", """processCreation {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}processCreation)""",
    """commandLine:\s*\\?["\\]*"+({command_line}[^"]+?)\\*"""",
  ]
}
```