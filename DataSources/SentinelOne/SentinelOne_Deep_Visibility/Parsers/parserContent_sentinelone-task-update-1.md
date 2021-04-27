#### Parser Content
```Java
{
Name = sentinelone-task-update-1
  DataType = "windows-task-created"
  Conditions = [ """"SentinelOne"""", """Deep Visibility Endpoint""", """schedTaskUpdate {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}schedTaskUpdate)""",
    """commandLine:\s*\\?["\\]*"+({command_line}[^"]+?)\\*"""",
    """taskName:\s*\\?"+\\*({task_name}[^"]+?)\\*""""
  ]
}
```