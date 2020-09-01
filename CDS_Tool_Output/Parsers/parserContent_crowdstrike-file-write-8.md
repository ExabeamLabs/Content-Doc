#### Parser Content
```Java
{
Name = crowdstrike-file-write-8
  DataType = "file-write"
  Conditions = [ """"event_simpleName\":\"PeFileWritten\"""", """"@timestamp"""" ]
  Fields = ${CrowdStrikeParserTemplates.crowdstrike-auth-activity.Fields} [
  ]
}
```