#### Parser Content
```Java
{
Name = crowdstrike-file-write-12
  DataType = "file-write"
  Conditions = [ """"event_simpleName\":\"DwgFileWritten\"""", """"@timestamp"""" ]
  Fields = ${CrowdStrikeParserTemplates.crowdstrike-auth-activity.Fields} [
  ]
}
```