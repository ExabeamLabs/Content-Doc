#### Parser Content
```Java
{
Name = crowdstrike-file-write-14
  DataType = "file-operations"
  Conditions = [ """"event_simpleName\":\"DirectoryCreate\"""", """"@timestamp"""" ]
  Fields = ${CrowdStrikeParserTemplates.crowdstrike-auth-activity.Fields} [
  ]
}
```