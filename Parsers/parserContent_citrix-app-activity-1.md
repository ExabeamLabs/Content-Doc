#### Parser Content
```Java
{
Name = citrix-app-activity-1
  DataType = "app-activity"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = ["""destinationServiceName=Citrix ShareFile""", """"ActivityType":""", """flexString1Label=application-action"""]
  Fields = ${CitrixParserTemplates.citrix-app-activity.Fields}[
    """({activity}resource-acl-updated)""",
    """"ActivityType"+:"+({activity}[^"]+)"""",
    """"TimeStamp"+:"({time}[^"]+)""",
  ]
}
```