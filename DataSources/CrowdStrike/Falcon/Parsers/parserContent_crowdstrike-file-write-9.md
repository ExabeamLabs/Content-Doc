#### Parser Content
```Java
{
Name = crowdstrike-file-write-9
  DataType = "file-write"
  Conditions = [ """"event_simpleName\":\"OoxmlFileWritten\"""", """"@timestamp"""" ]
  Fields = ${CrowdStrikeParserTemplates.crowdstrike-auth-activity.Fields} [
  ]
}
```