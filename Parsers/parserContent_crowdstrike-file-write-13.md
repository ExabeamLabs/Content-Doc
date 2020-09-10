#### Parser Content
```Java
{
Name = crowdstrike-file-write-13
  DataType = "file-write"
  Conditions = [ """"event_simpleName\":\"DmpFileWritten\"""", """"@timestamp"""" ]
  Fields = ${CrowdStrikeParserTemplates.crowdstrike-auth-activity.Fields} [
  ]
}
```