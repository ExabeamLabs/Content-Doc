#### Parser Content
```Java
{
Name = crowdstrike-win-task-created
  DataType = "windows-task-created"
  Conditions = [ """"event_simpleName":"ScheduledTaskRegistered""", """"event_platform":"Win""""]
  Fields = ${CrowdStrikeParserTemplates.cef-crowdstrike-app-activity-temp.Fields} [
    """"TaskName":"({task_name}[^"]+)"""
  ]
}
```