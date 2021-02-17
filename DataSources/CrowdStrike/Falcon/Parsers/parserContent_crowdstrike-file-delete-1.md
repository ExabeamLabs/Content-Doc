#### Parser Content
```Java
{
Name = crowdstrike-file-delete-1
  DataType = "file-write"
  Conditions = [ """"event_simpleName\":\"ExecutableDeleted\"""", """"@timestamp"""" ]
  Fields = ${CrowdStrikeParserTemplates.crowdstrike-auth-activity.Fields} [
  ]
}
```