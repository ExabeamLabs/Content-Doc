#### Parser Content
```Java
{
Name = crowdstrike-file-write-10
  DataType = "file-write"
  Conditions = [ """"event_simpleName\":\"OleFileWritten\"""", """"@timestamp"""" ]
  Fields = ${CrowdStrikeParserTemplates.crowdstrike-auth-activity.Fields} [
  ]
}
```