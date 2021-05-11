#### Parser Content
```Java
{
Name = sentinelone-task-update-1
  DataType = "windows-task-created"
  Conditions = [ """"SentinelOne"""", """Deep Visibility Endpoint""", """schedTaskUpdate {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}schedTaskUpdate)""",
    """commandLine:\s{0,100}\\?["\\]*"{1,20}({command_line}[^"]+?)\\*"""",
    """taskName:\s{0,100}\\?"{1,20}\\*({task_name}[^"]+?)\\*""""
  ]
}
```