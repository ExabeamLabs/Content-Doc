#### Parser Content
```Java
{
Name = crowdstrike-file-read-2
  DataType = "file-operations"
  Conditions = [ """"event_simpleName\":\"CriticalFileAccessed\"""", """"@timestamp"""" ]
  Fields = ${CrowdStrikeParserTemplates.crowdstrike-auth-activity.Fields} [
  ]
}
```