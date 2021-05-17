#### Parser Content
```Java
{
Name = sentinelone-task-update-1
  DataType = "windows-task-created"
  Conditions = [ """"SentinelOne"""", """Deep Visibility Endpoint""", """schedTaskUpdate {""" ]
  Fields = ${SentinelOneParserTemplates.sentinelone-activity.Fields} [
    """({event_name}schedTaskUpdate)""",
    """commandLine:\s{0,100}\\?["\\]{0,2000}"{1,20}({command_line}[^"]{1,2000}?)\\*"""",
    """taskName:\s{0,100}\\?"{1,20}\\*({task_name}[^"]{1,2000}?)\\*""""
  ]
}
```